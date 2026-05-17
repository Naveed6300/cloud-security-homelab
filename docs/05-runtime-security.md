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

## Step 1 — Prepare Gatekeeper and install Falco

### 1a. Exempt the security namespace from Gatekeeper constraints

Phase 04's admission policies will block Falco from scheduling. Falco needs `privileged: true` to load its eBPF probe and read host syscalls — the `pod-deny-privileged` constraint rejects this. The `pods-require-resource-limits` constraint also blocks Falco's init containers, which don't set limits. Exempt the `security` namespace from both before installing:

```bash
# Exempt security from the privileged constraint
$ kubectl patch k8spspprivilegedcontainer pod-deny-privileged --type merge -p '
spec:
  match:
    excludedNamespaces:
      - kube-system
      - gatekeeper-system
      - security
'

# Remove security from the resource-limits enforcement list
# (the constraint uses an explicit namespaces include list, not excludedNamespaces)
$ kubectl patch k8srequiredresourcelimits pods-require-resource-limits --type merge -p '
spec:
  match:
    namespaces:
      - storage
      - default
'
```

Also add `docker.io/redis/` to your registry allowlist — the Falcosidekick UI requires it for its Redis dependency:

```bash
$ kubectl edit k8sallowedrepos pod-allowed-registries
# add: - "docker.io/redis/"  to the registries list under spec.parameters
```

Update your constraint files in the repo to match these changes.

### 1b. Install Falco

```bash
$ helm repo add falcosecurity https://falcosecurity.github.io/charts
$ helm repo update

$ kubectl create namespace security
```

Read `manifests/05-runtime/falco-values.yaml` end to end. Important choices:

- `driver.kind: modern_ebpf` — use the CO-RE eBPF driver (see note below)
- `falcosidekick.enabled: true` — install the forwarder alongside Falco
- `falcosidekick.webui.enabled: true` — installs a small UI at port 2802 for browsing alerts locally
- `falco.json_output: true` — emit alerts as JSON rather than text (Elasticsearch wants this)
- `falco.json_include_output_property: true` — include the human-readable message in the JSON
- `falco.json_include_tags_property: true` — include ATT&CK tags in the JSON (enables technique-based Kibana filtering)

> **Why `modern_ebpf`, not `ebpf`:** The legacy `ebpf` driver tries to download a prebuilt probe for your kernel version, then falls back to compiling it. On Ubuntu 24.04 with kernel 6.8+, no prebuilt probe is available and the compile fallback fails with a GLIBC version mismatch between the driver-loader container and the downloaded kernel headers. `modern_ebpf` uses CO-RE (Compile Once, Run Everywhere) — it ships a single eBPF object that reads BTF from the kernel at runtime, requires no per-kernel probe download or compilation, and starts in seconds. Any kernel 5.8+ with BTF enabled (default on Ubuntu) supports it.

```bash
$ helm install falco falcosecurity/falco \
    --namespace security \
    -f manifests/05-runtime/falco-values.yaml
```

Wait for Falco to roll out. It runs as a DaemonSet — one pod per node:

```bash
$ kubectl -n security get pods
# 3 falco pods (one per node), 1 falcosidekick, 1 falcosidekick-ui, 1 redis

$ kubectl -n security logs daemonset/falco --tail=20
# look for "Starting detection engine" — confirms rules are loaded
```

---

## Step 2 — Access the Falcosidekick UI

Two access methods. Pick one.

**Option A — port-forward (on-demand, no persistent config):**

```bash
$ kubectl -n security port-forward svc/falco-falcosidekick-ui 2802:2802
# then: http://localhost:2802
```

**Option B — Ingress (persistent browser access):**

Add to `manifests/05-runtime/falco-values.yaml` under the falcosidekick block and run `helm upgrade`:

```yaml
falcosidekick:
  webui:
    ingress:
      enabled: true
      ingressClassName: traefik
      hosts:
        - host: falco.lab.home.arpa
          paths:
            - path: /
              pathType: Prefix
```

Then add `192.168.2.130  falco.lab.home.arpa` to your Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`). Access via `http://falco.lab.home.arpa`.

**Default credentials:** `admin` / `admin`

Open the UI and keep it visible through the next step — alerts appear in real time as they fire.

---

## Step 3 — Generate detections

Each of these maps to a default Falco rule. The point is to feel what triggers what, and to save evidence of working detections.

> **Run test pods in the `security` namespace.** The `default` namespace is covered by the `pods-require-resource-limits` Gatekeeper constraint and will reject pods without resource limits. The `security` namespace is exempted.

### Detection 1 — "Terminal shell in container"

```bash
# Create a test pod in the security namespace
$ kubectl run shellme --image=docker.io/library/alpine \
    --restart=Never -n security -- sleep 3600

# Wait for it to be Running
$ kubectl -n security wait --for=condition=Ready pod/shellme

# Exec into it (this is the trigger)
$ kubectl exec -it shellme -n security -- sh
/ # exit
```

In the Falcosidekick UI you should see **"Terminal shell in container"** at NOTICE severity, tagged `T1059 / mitre_execution`. The alert payload includes container ID, image, command, and the parent process (your kubectl exec).

Save the JSON payload:
```bash
$ kubectl -n security logs -l app.kubernetes.io/name=falco --tail=50 \
    | grep "Terminal shell" | head -1 | jq . > scans/falco-shell-alert.json
```

### Detection 2 — "Read sensitive file untrusted"

```bash
$ kubectl exec -it shellme -n security -- sh
/ # cat /etc/shadow
/ # exit
```

Alert: **"Read sensitive file untrusted"** at WARNING severity, tagged `T1555 / mitre_credential_access`.

### Detection 3 — "Package manager run in container" + "Drop and execute new binary"

```bash
$ kubectl exec -it shellme -n security -- sh
/ # apk add curl --no-cache
/ # exit
```

This triggers two alerts:
- **"Package manager run in container"** (your custom rule, WARNING, T1072)
- **"Drop and execute new binary in container"** (default Falco rule, CRITICAL) — fires because `curl` was downloaded and executed from a path not in the original container image layer

The CRITICAL alert on binary drop is one of Falco's highest-signal default rules — it catches the pattern of an attacker downloading a tool into a running container.

Save the alert JSON:
```bash
$ kubectl -n security logs -l app.kubernetes.io/name=falco --tail=100 \
    | grep -v "Redirect STDOUT" \
    | grep "Package manager\|Drop and execute" \
    | head -2 | jq -s . > scans/falco-custom-rule-cred.json
```

> **Filtering Longhorn noise:** Falco's "Redirect STDOUT/STDIN to Network Connection in Container" rule fires continuously from Longhorn's storage manager doing normal backup operations. This is a false positive — Longhorn legitimately uses `dup3` syscalls that match the rule signature. Filter it with `grep -v "Redirect STDOUT"` when reading logs, and suppress it in Falcosidekick using the UI's filter feature. In production this is resolved by adding a process-name exception to the rule in `custom-rules.yaml`. This is the alert tuning problem that occupies real SOC engineering time.

Clean up:
```bash
$ kubectl -n security delete pod shellme
```

---

## Step 4 — Write custom rules

The default rules are a starting point. Production deployments add custom rules tied to *your* environment's threat model.

### Deploying custom rules — the right way

The Falco helm chart's `customRules:` values key is the supported mechanism. The chart creates a ConfigMap from it and mounts it at `/etc/falco/rules.d/`. Do **not** apply a separate ConfigMap with `kubectl apply` — it won't be mounted in the Falco pods unless you also configure `extraVolumes`/`extraVolumeMounts` in the DaemonSet.

Add custom rules inline in `manifests/05-runtime/falco-values.yaml`:

```yaml
customRules:
  custom-rules.yaml: |-
    - rule: Cloud credential file read
      desc: >
        Reading common cloud credential file paths in any container. Maps to
        MITRE ATT&CK T1552.001 (Credentials in Files).
      condition: >
        open_read and container and
        (fd.name endswith /.aws/credentials or
         fd.name endswith /.aws/config or
         fd.name endswith /.azure/credentials or
         fd.name endswith /.mc/config.json or
         fd.name endswith /.config/gcloud/credentials.db)
      output: >
        Cloud credential file read
        (user=%user.name proc=%proc.name file=%fd.name
        container=%container.name pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [credentials, mitre_credential_access, T1552_001]

    - rule: Package manager run in container
      desc: Detects package manager execution inside a container (T1072)
      condition: >
        spawned_process and container and
        proc.name in (apk, apt, apt-get, yum, dnf, pip, pip3)
      output: >
        Package manager launched in container
        (user=%user.name proc=%proc.name cmd=%proc.cmdline
        container=%container.name pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [container, T1072, mitre_lateral_movement]

    - rule: Unauthorized write to Postgres data dir
      desc: Detect writes to /var/lib/postgresql/data by anything other than postgres
      condition: >
        open_write and container and
        fd.name startswith /var/lib/postgresql/data and
        not proc.name in (postgres, pg_ctl, initdb, pg_basebackup)
      output: >
        Unexpected write to Postgres data dir
        (user=%user.name proc=%proc.name file=%fd.name container=%container.name)
      priority: WARNING
      tags: [database, integrity, mitre_impact]
```

Apply via helm:

```bash
$ helm -n security upgrade falco falcosecurity/falco \
    --values manifests/05-runtime/falco-values.yaml \
    --reuse-values

$ kubectl -n security rollout status daemonset/falco

# Confirm rules are loaded
$ POD=$(kubectl -n security get pods -l app.kubernetes.io/name=falco -o name | head -1)
$ kubectl -n security exec $POD -c falco -- \
    falco --list-rules 2>/dev/null | grep -E "credential|package|postgres"
```

### Test the credential read rule

```bash
$ kubectl run cred-test --image=docker.io/library/alpine \
    --restart=Never -n security -- sleep 3600

$ kubectl exec -it cred-test -n security -- sh
/ # mkdir -p /root/.aws && echo "[default]" > /root/.aws/credentials
/ # cat /root/.aws/credentials
/ # exit

$ kubectl -n security delete pod cred-test
```

Alert: **"Cloud credential file read"** at WARNING, tagged `T1552_001 / mitre_credential_access`. Save the JSON to `scans/falco-custom-rule-cred.json`. You now have a custom rule mapped to a specific ATT&CK technique, demonstrating the threat-model-to-detection pipeline.

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

**Falco DaemonSet stuck at CURRENT=0 (Gatekeeper blocking).**
The most common failure on first install. Run `kubectl -n security describe daemonset falco | tail -20` — the Events section will show Gatekeeper rejections. Two constraints typically fire: `pod-deny-privileged` (Falco needs privileged for eBPF) and `pods-require-resource-limits` (Falco's init containers don't set limits). Fix: exempt the `security` namespace from both constraints as described in Step 1a. Gatekeeper re-evaluates on next pod creation attempt — the DaemonSet will converge within 30 seconds of applying the patch.

**Falco driver-loader CrashLoopBackOff: GLIBC mismatch / no prebuilt probe.**
Check the logs: `kubectl -n security logs <falco-pod> -c falco-driver-loader`. If you see `Non-200 response... 404` followed by `GLIBC_2.38 not found`, you're on the legacy `ebpf` driver. The driver-loader container's base image is too old to compile against the kernel headers for your kernel. Fix: set `driver.kind: modern_ebpf` in `falco-values.yaml` and `helm upgrade`. The modern_ebpf driver uses CO-RE eBPF and doesn't compile anything — it works on any kernel 5.8+ with BTF enabled (default on Ubuntu 22.04+).

**Falcosidekick UI stuck at 0/1 (Redis blocked by registry allowlist).**
The UI depends on `docker.io/redis/redis-stack`. If your `pod-allowed-registries` Gatekeeper constraint doesn't include `docker.io/redis/`, the Redis StatefulSet and the UI Deployment will fail to schedule with a Gatekeeper admission error. Fix: add `"docker.io/redis/"` to the registries list in `manifests/04-supply-chain/03-allowed-registries-constraint.yaml` and `kubectl apply -f` it.

**Longhorn alert noise drowning your detections.**
The "Redirect STDOUT/STDIN to Network Connection in Container" rule fires every few minutes from Longhorn's backup manager — hundreds of times per hour. It's a true-positive-technically (the `dup3` syscall matches the rule) but a false-positive operationally (Longhorn's behavior is legitimate). Filter it when grepping logs with `grep -v "Redirect STDOUT"`. To suppress at the rule level, add an exception in `customRules`:
```yaml
- rule: Redirect STDOUT/STDIN to Network Connection in Container
  exceptions:
    - name: longhorn_storage
      fields: [proc.name]
      comps: [in]
      values:
        - [longhorn, longhorn-instan]
```

**Custom rules not loading (separate ConfigMap approach).**
If you apply `custom-rules.yaml` as a standalone ConfigMap with `kubectl apply`, Falco won't pick it up — the DaemonSet doesn't know to mount it. The chart-supported method is the `customRules:` values key in `falco-values.yaml` (which the chart mounts automatically at `/etc/falco/rules.d/`). The separate ConfigMap approach requires `extraVolumes` and `extraVolumeMounts` in the chart values, which adds complexity for no benefit.

**No alerts from `cat /etc/shadow` or package manager.**
Both rules (`Read sensitive file untrusted` and `Launch Package Management Process in Container`) were moved to `falco-incubating-rules` in Falco 0.37+. They're not loaded by default. The package manager rule is covered by the custom `Package manager run in container` rule in this lab. For the sensitive file rule, either load incubating rules via falcoctl or write your own.

**Falco running but Falcosidekick can't reach Security Onion: TLS errors.**
SO uses a self-signed cert. For the lab, set `minTLSVersion: ""` in the Elasticsearch config block in `falco-values.yaml`. In production, mount the SO CA cert into Falcosidekick.

**Falcosidekick reaches SO but no events appear in Kibana.**
Check the API key has `manage_index` privilege on the target index. Falcosidekick logs show every send attempt with HTTP status: `kubectl -n security logs deployment/falco-falcosidekick`.

---

## Key takeaways

- Falco runs as a DaemonSet on a 3-node k3s cluster, capturing syscalls via eBPF. Detections fire for shell-in-container, sensitive file reads, and outbound network activity. Alerts forward to Security Onion via Falcosidekick, where a Kibana dashboard supports triage.
- Custom Falco rules tie to environment-specific threat models — including one mapped to MITRE ATT&CK T1552.001 for credential file access in containers.
- Detection vs prevention: Falco is a detection tool; preventing the behavior would require integration with admission control or a runtime enforcement tool. Detection is the right default in a multi-tenant cluster — false-positive cost (operational drag) is lower than false-negative cost (missed compromise).
- Multi-layer detection pipeline: container runtime (Falco), network IDS (Suricata via Security Onion), endpoint telemetry (Sysmon via Elastic Agent on Windows endpoints), and Zeek for network metadata. Everything terminates in the same Kibana for unified triage.

## Next

Phase 06 — [Network policy](06-network-policy.md). You'll add a default-deny NetworkPolicy and explicitly allow only the flows the lab needs. Then phase 07 layers in posture management with kube-bench and Kubescape.
