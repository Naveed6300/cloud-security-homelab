# Phase 05 — Runtime Security with Falco

**Goal:** deploy Falco, generate runtime detections in your k3s cluster, write two custom rules, and forward alerts to your existing Security Onion deployment for centralized visibility.

**Time budget:** 3 hours. The Falco install is fast; the Security Onion integration takes the most time.

**Why this matters:** runtime detection closes the loop on cloud security. You can scan an image (phase 04) and you can block bad pod specs at admission (phase 04). Neither catches a *running* container that suddenly spawns a shell, reads `/etc/shadow`, or reaches out to a malicious IP. Falco does. And shipping alerts to Security Onion gives a single pane of glass across network, endpoint, and container — the multi-layer detection model.

**You will end up with:**
- Falco running as a DaemonSet on every node, watching syscalls
- Three deliberate detections triggered and saved as evidence
- Two custom Falco rules tailored to your environment
- Falcosidekick forwarding alerts to Security Onion
- Falco events queryable in Security Onion's Kibana

---

## Concepts

### What Falco actually watches

Falco is a runtime security tool that hooks into the Linux kernel and observes syscalls — the lowest-level interaction between a process and the OS. When a process opens a file, makes a network connection, executes a binary, or reads `/etc/passwd`, that's a syscall. Falco sees every one across every container on every node.

It then evaluates each syscall against a rule set. A rule is something like: "if a shell binary (bash, sh, zsh) is executed inside a container, alert." The default rule set ships with ~80 rules covering common attacker behaviors — privilege escalation, container breakouts, sensitive file reads, suspicious network connections, crypto-mining patterns.

### eBPF vs kernel module — pick eBPF

Falco has two ways to capture syscalls:
- **Kernel module** — older, requires a kernel module compiled for your specific kernel version. Reliable but invasive.
- **eBPF probe** — newer, runs in the kernel via the eBPF VM, no kernel module install needed. The community-supported default since Falco 0.34.

Always use eBPF unless you have a specific reason not to. We do.

### What Falco doesn't do

Falco is **detection, not prevention**. It alerts when a rule matches; it doesn't kill the process or block the syscall. There are projects (Falco Talon, kubectl admission integrations) that can act on Falco alerts, but the canonical model is: Falco detects, your SOC responds.

This is the right separation of concerns. Inline blocking carries risk (false positives become outages). Detection-first is how almost every production deployment is structured.

### Falcosidekick — the alert forwarder

Falco's default output is stdout (or local syslog). For real deployments you want alerts to reach a SIEM, ticketing system, chat channel, or webhook. **Falcosidekick** is a small companion service that listens for Falco alerts and routes them to ~50 different backends: Elasticsearch, Splunk, Slack, PagerDuty, AWS SNS, generic webhooks, and so on.

For this lab, we use Falcosidekick to forward alerts to **Security Onion**, which already runs Elasticsearch + Kibana. There are three integration patterns to choose between:

| Pattern | How it works | Pros | Cons |
|---|---|---|---|
| Webhook to Logstash | Falcosidekick POSTs JSON to a custom Logstash listener on SO | Most flexible | Requires SO Logstash config tweak |
| Direct Elasticsearch | Falcosidekick writes directly to SO's Elasticsearch | Simplest | Bypasses SO's normalization pipeline |
| Syslog to SO | Falcosidekick sends RFC 5424 syslog to SO's syslog port | Looks like other SO log sources | Loses some JSON structure |

We'll use **direct Elasticsearch**. It's the simplest path and gets alerts visible in Kibana within a minute. In production you'd choose Logstash to get proper enrichment and ECS field mapping.

---

## Prerequisites

- Phases 02 and 04 complete. You have running workloads to detect against.
- Security Onion reachable on the network from your k3s cluster. Note the management IP — we'll use `<so-mgmt-ip>` throughout.
- An Elasticsearch API key from Security Onion (we'll create one in step 4).
- The OPA Gatekeeper `K8sAllowedRepos` constraint includes `docker.io/falcosecurity/` (already done in `manifests/04-supply-chain/03-allowed-registries-constraint.yaml`).

---

## Step 1 — Install Falco

```bash
$ helm repo add falcosecurity https://falcosecurity.github.io/charts
$ helm repo update

$ kubectl create namespace security
```

Read `manifests/05-runtime/falco-values.yaml` end to end. Important choices:

- `driver.kind: ebpf` — the modern eBPF driver
- `falcosidekick.enabled: true` — install the forwarder alongside Falco
- `falcosidekick.webui.enabled: true` — installs a small UI at port 2802 for browsing alerts locally (handy for development)
- `falco.json_output: true` — emit alerts as JSON rather than text (Elasticsearch wants this)
- `falco.json_include_output_property: true` — include the human-readable message in the JSON

```bash
$ helm install falco falcosecurity/falco \
    --namespace security \
    -f manifests/05-runtime/falco-values.yaml
```

Wait for Falco to roll out. It runs as a DaemonSet — one pod per node:

```bash
$ kubectl -n security get pods
# 3 falco pods (one per node), 1 falcosidekick, 1 falcosidekick-ui
```

Tail Falco logs to confirm rules are loaded:

```bash
$ kubectl -n security logs daemonset/falco | grep -i "loaded"
# look for "Loaded N rules from N files"
```

---

## Step 2 — Watch Falco's UI

Port-forward the Falcosidekick UI to your workstation:

```bash
$ kubectl -n security port-forward svc/falco-falcosidekick-ui 2802:2802
```

Open `http://localhost:2802` in a browser. You'll see an empty alert feed. Keep this tab open through the next step.

---

## Step 3 — Generate three detections

Each of these maps to a default Falco rule. The point is to feel what triggers what, and to save evidence of working detections.

### Detection 1 — "Terminal shell in container"

```bash
# Create a vanilla pod
$ kubectl run shellme --image=docker.io/library/alpine --restart=Never -- sleep 3600

# Wait for it to be Running
$ kubectl wait --for=condition=Ready pod/shellme

# Exec into it (this is the trigger)
$ kubectl exec -it shellme -- sh
# Inside the pod:
/ #
/ # exit
```

In the Falcosidekick UI, you should see an alert: **"A shell was spawned in a container with an attached terminal"** at NOTICE severity. The alert payload includes the container ID, image, command (`sh`), user, and the parent process (your kubectl-exec).

Save the JSON payload to `scans/falco-shell-alert.json` as detection evidence.

### Detection 2 — "Sensitive file read"

Still inside (or back inside) the pod:

```bash
$ kubectl exec -it shellme -- sh
/ # cat /etc/shadow
```

The alert: **"Sensitive file read by trusted program after startup"** or **"Read sensitive file untrusted"**. WARNING or NOTICE severity depending on rule. Save it.

### Detection 3 — "Outbound connection to suspicious destination"

```bash
$ kubectl exec -it shellme -- sh
/ # apk add curl --no-cache
/ # curl http://example.com  # benign — won't trigger
/ # nc -zv 1.1.1.1 53        # UDP/TCP probe — may trigger "Outbound connection from container"
```

Some rules require additional context (known bad IP lists, mining pool ports, etc.) — you may not get a "high-severity" hit on a benign destination. That's actually a useful learning: Falco's default ruleset is conservative to avoid noise. **Custom rules** (next step) are how you encode your own threat model.

Clean up:

```bash
$ kubectl delete pod shellme
```

---

## Step 4 — Write two custom rules

The default rules are a starting point. Production deployments add custom rules tied to *your* environment's threat model.

### Custom rule 1: alert when anything writes to a Postgres data directory from outside the postgres process

Open `manifests/05-runtime/custom-rules.yaml` and read it. The relevant rule:

```yaml
- rule: Unauthorized write to Postgres data dir
  desc: Detect writes to /var/lib/postgresql/data by anything other than postgres
  condition: >
    open_write and
    fd.name startswith /var/lib/postgresql/data and
    not proc.name in (postgres, pg_ctl, initdb)
  output: >
    Unexpected write to Postgres data dir
    (user=%user.name proc=%proc.name file=%fd.name container=%container.name)
  priority: WARNING
  tags: [database, integrity]
```

This catches: an attacker shells into the Postgres container and tries to tamper with the data files directly.

### Custom rule 2: alert on access keys being read in containers

```yaml
- rule: AWS or MinIO credential file read
  desc: Reading common cloud credential file paths in a container
  condition: >
    open_read and
    (fd.name endswith /.aws/credentials or
     fd.name endswith /.aws/config or
     fd.name endswith /.mc/config.json)
  output: >
    Cloud credential file read
    (user=%user.name proc=%proc.name file=%fd.name container=%container.name)
  priority: WARNING
  tags: [credentials, mitre_credential_access]
```

This maps to MITRE ATT&CK **T1552.001 (Credentials in Files)**. It's a classic post-exploitation move.

Apply the custom rules:

```bash
$ kubectl apply -f manifests/05-runtime/custom-rules.yaml
$ kubectl -n security rollout restart daemonset/falco
$ kubectl -n security rollout status daemonset/falco
```

Test rule 2:

```bash
$ kubectl run cred-test --image=docker.io/library/alpine --restart=Never -- sleep 3600
$ kubectl exec -it cred-test -- sh
/ # mkdir -p /root/.aws && echo "[default]" > /root/.aws/credentials
/ # cat /root/.aws/credentials
# alert fires
```

Save the alert JSON to `scans/falco-custom-rule-cred.json`. You now have a custom rule mapped to a specific ATT&CK technique, demonstrating the threat-model-to-detection pipeline.

---

## Step 5 — Forward to Security Onion

Now wire Falcosidekick to Security Onion's Elasticsearch.

### 5a. Get an Elasticsearch API key from Security Onion

On the Security Onion node:

```bash
# SSH in
$ ssh socadmin@<so-mgmt-ip>
$ sudo so-elasticsearch-apikey -n falco-ingest -r superuser
```

This produces a JSON output with `api_key` and `id`. The `encoded` field is what Falcosidekick needs. Save it — you can't retrieve it again.

> **Security Onion uses a self-signed cert.** You'll either need to disable cert verification (lab-only) or import the SO CA into Falcosidekick. For the lab, we'll skip verification.

### 5b. Update the Falcosidekick config to point at SO's Elasticsearch

Edit `manifests/05-runtime/falcosidekick-config.yaml`. Set:

```yaml
elasticsearch:
  hostport: "https://<so-mgmt-ip>:9200"
  index: "falco-events"
  apiKey: "<paste-the-encoded-api-key-here>"
  # MinTLSVersion bypass for self-signed cert. Lab only.
  customSeverityMap: ""
```

**Don't commit the API key.** Use a separate `falcosidekick-secrets.yaml` (gitignored) and reference it in the Helm install.

```bash
$ helm upgrade falco falcosecurity/falco \
    --namespace security \
    -f manifests/05-runtime/falco-values.yaml \
    -f manifests/05-runtime/falcosidekick-secrets.yaml
```

### 5c. Trigger an alert and look for it in Kibana

```bash
$ kubectl run shellme2 --image=alpine --restart=Never -- sleep 3600
$ kubectl exec -it shellme2 -- sh
/ # exit
$ kubectl delete pod shellme2
```

Open Security Onion's Kibana at `https://<so-mgmt-ip>` (or whatever URL you use) and search the `falco-events-*` index pattern. The alert you just generated should be there with all its fields (rule, priority, output, container details, source).

If Kibana doesn't have a `falco-events-*` index pattern, create one in Stack Management → Index Patterns.

---

## Step 6 — Build a saved search and a basic dashboard in Kibana

This is what makes the deliverable production-shaped rather than just "I sent some logs to a tool."

In Kibana:

1. **Discover** → select `falco-events-*` → save a search called "Falco — high-priority" filtered to `priority: ("CRITICAL" or "ERROR" or "WARNING")`.
2. **Dashboards** → create a new dashboard "Falco Runtime Detection" with:
   - A line chart: alert count over time
   - A pie chart: alerts by rule name
   - A data table: top 10 rules by count
3. Save and screenshot the dashboard. Add the screenshot to your repo at `docs/images/falco-dashboard.png`.

---

## Validation checklist

- [ ] `kubectl -n security get pods` shows three Falco pods Running and one Falcosidekick Running
- [ ] Falco logs show "Loaded N rules from N files" with N matching default + your custom rules
- [ ] Falcosidekick UI shows alerts when you trigger them
- [ ] You have three saved alert JSON files in `scans/`
- [ ] Custom rule for cloud credentials triggers when expected
- [ ] Security Onion Kibana shows Falco events in a `falco-events-*` index pattern
- [ ] Saved Kibana search and dashboard exist
- [ ] No API keys committed to the repo

---

## Troubleshooting

**Falco pods CrashLoopBackOff with "kernel module load failed".** You're probably hitting the kernel-module driver instead of eBPF. Confirm `driver.kind: ebpf` in your values.

**Falco running but no alerts.** Check the rule set loaded: `kubectl -n security exec ds/falco -- falco --list`. Then trigger something definitively in scope, like `kubectl exec` into a pod (always triggers shell rule). If still silent, look at `journalctl -u falco` on the node — it may be that the eBPF probe isn't loading.

**Falcosidekick can't reach Security Onion: TLS errors.** SO uses a self-signed cert. For the lab, set `elasticsearch.minTLSVersion: ""` and accept the risk. In production, mount the SO CA cert into Falcosidekick.

**Falcosidekick reaches SO but no events appear in Kibana.** Check the API key has `superuser` or at least `manage_index` privilege on the target index. Falcosidekick logs show every send attempt with HTTP status — `kubectl -n security logs deployment/falco-falcosidekick`.

**Too many alerts, can't see the signal.** Falco's defaults are noisy in a lab because everything looks like attacker behavior. Tune by:
1. Adding `tags: [noisy_in_lab]` to specific rules and excluding them in Falcosidekick filters
2. Setting some rules to PRIORITY=DEBUG so they don't forward
3. Using Falco's `lists` and `macros` to whitelist your known-good operations

**A custom rule isn't firing.** `kubectl -n security exec ds/falco -- falco --validate /etc/falco/falco_rules.local.yaml` will show parse errors. Then check the rule's condition matches — Falco has a verbose mode (`-vv`) that logs every condition evaluation.

---

## Key takeaways

- Falco runs as a DaemonSet on a 3-node k3s cluster, capturing syscalls via eBPF. Detections fire for shell-in-container, sensitive file reads, and outbound network activity. Alerts forward to Security Onion via Falcosidekick, where a Kibana dashboard supports triage.
- Custom Falco rules tie to environment-specific threat models — including one mapped to MITRE ATT&CK T1552.001 for credential file access in containers.
- Detection vs prevention: Falco is a detection tool; preventing the behavior would require integration with admission control or a runtime enforcement tool. Detection is the right default in a multi-tenant cluster — false-positive cost (operational drag) is lower than false-negative cost (missed compromise).
- Multi-layer detection pipeline: container runtime (Falco), network IDS (Suricata via Security Onion), endpoint telemetry (Sysmon via Elastic Agent on Windows endpoints), and Zeek for network metadata. Everything terminates in the same Kibana for unified triage.

## Next

Phase 06 — [Network policy](06-network-policy.md). You'll add a default-deny NetworkPolicy and explicitly allow only the flows the lab needs. Then phase 07 layers in posture management with kube-bench and Kubescape.
