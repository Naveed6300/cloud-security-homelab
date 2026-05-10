# Phase 10 — Incident Response Runbook

**Goal:** convert one Falco detection into a concrete, end-to-end IR playbook. Walk through what an analyst would do from the moment the alert fires to the moment the incident is closed and the lesson learned is captured.

**Time budget:** 1 hour to write, plus a tabletop walk-through.

**Why this exists:** the JD calls out "developing and maintaining cloud incident response runbooks." Most candidates can talk about generic IR phases (prepare → detect → contain → eradicate → recover → learn). Few can walk a panel through a specific runbook with the actual commands. That's the bar this doc clears.

**Scenario picked:** T1552.001 — Credentials in Files, fired by your custom Falco rule from Phase 05 (`Cloud credential file read`). This is one of the most realistic post-exploitation moves in cloud and you have the detection wired already.

---

## Concepts

### Why runbooks exist

When an alert fires at 2 AM, the on-call engineer should not be inventing a response. They should be executing a pre-written, peer-reviewed sequence of steps. Runbooks reduce time-to-contain (TTC), reduce mistakes during high-stress response, and make incidents auditable after the fact.

A good runbook has four properties:

1. **Triggered by a specific signal.** "When this rule fires, run this runbook." Not "for any cloud incident."
2. **Decision points are explicit.** "If the affected resource is in production, page the incident commander. If non-prod, escalate at 30 minutes."
3. **Commands are concrete.** "Run `kubectl cordon <node>`" not "isolate the affected node."
4. **Has a clear end state.** "The runbook is closed when X, Y, Z are true."

### IR phases (NIST SP 800-61 Rev. 2)

Every runbook walks the same phases. Mapping them to this scenario:

| NIST phase | Goal | This runbook |
|---|---|---|
| Preparation | Have the tools, contacts, and authority to act | Falco + Sec Onion + this runbook + IAM access to revoke keys |
| Detection & Analysis | Confirm the alert is real and characterize the incident | Pull alert from Sec Onion, inspect pod, decide severity |
| Containment | Stop the bleeding without making evidence-collection harder | Cordon node, isolate pod via NetworkPolicy, rotate credentials |
| Eradication | Remove the attacker's foothold | Delete the pod, rebuild the image, patch the entry vector |
| Recovery | Restore service and validate | Redeploy from a clean image, verify monitoring, monitor for recurrence |
| Post-incident | Capture lessons | Tag the incident, write a postmortem, file follow-up tickets |

---

# Runbook: Cloud Credential File Read in Container

**Trigger:** Falco rule `Cloud credential file read` fires (custom rule, mapped to ATT&CK T1552.001)
**Severity:** High (default). Escalate to Critical if the container is part of a production-tier workload.
**Estimated TTC:** 15 minutes for containment if you follow this runbook.

## 0. Preparation (done in advance, not during incident)

Before you can run this playbook, the following must be true:

- [ ] Falco custom rule deployed and confirmed firing (Phase 05)
- [ ] Falcosidekick → Security Onion pipeline working (Phase 05)
- [ ] You have an IAM identity with permission to revoke AWS access keys / MinIO service accounts
- [ ] You have an emergency-break-glass kubeconfig with cluster-admin (kept offline)
- [ ] Slack channel or pager configured to receive alerts on this rule
- [ ] On-call rotation defined; primary and secondary on-call contacts known
- [ ] Communication template ready — who to notify, what to say, in what order

If any of these aren't true, you're not ready to respond — fix preparation gaps before you need them.

---

## 1. Detection & Analysis

Goal: confirm the alert is real, not noisy. Characterize the incident.

### 1.1 Pull the alert from Security Onion

In Kibana, search the `falco-events-*` index pattern with the alert ID or rule name:

```
rule.name: "Cloud credential file read"
```

Open the most recent event. Expected fields:

```json
{
  "rule": "Cloud credential file read",
  "priority": "Warning",
  "output": "Cloud credential file read (user=root proc=cat file=/root/.aws/credentials container=...)",
  "k8s.ns.name": "<namespace>",
  "k8s.pod.name": "<pod>",
  "container.image.repository": "<image>",
  "proc.cmdline": "cat /root/.aws/credentials",
  "user.name": "root",
  "evt.time": "..."
}
```

Capture the values for:
- `k8s.ns.name`
- `k8s.pod.name`
- `container.image.repository`
- `evt.time`
- `proc.cmdline` and `proc.pname` (parent process — was this a shell?)

Save the JSON to your incident workspace. Don't lose it.

### 1.2 Validate the alert — is this expected behavior?

Some apps legitimately read AWS credentials at startup. Decide:

- Is the container *supposed* to use AWS creds at runtime? If yes — does it normally read them at this time? Once at startup vs. continuously?
- Is the parent process expected? (e.g., the AWS SDK reading creds on init is fine; a shell reading them is not)
- Is the user expected? (root in a typical workload? probably not)

A quick check:

```bash
$ kubectl -n <ns> describe pod <pod> | grep -A 5 "Image\|Started\|State"
$ kubectl -n <ns> get pod <pod> -o jsonpath='{.metadata.creationTimestamp}'
```

**Decision point:**
- If the alert matches a *known* startup pattern → **mark as benign in Falco**, move on. Tune the rule to exclude this pattern.
- If the alert matches no expected behavior → **proceed to containment.**

### 1.3 Severity assignment

Default: **High**. Bump to **Critical** if any of:

- The container has access to production data
- The credentials read could pivot to other systems (cross-account roles, VPC peering)
- Multiple alerts in quick succession (suggests automation, not a one-off curiosity)
- Alert source is an internet-facing pod (Nextcloud, etc.)

Document the severity with a one-line justification.

---

## 2. Containment

Goal: prevent further damage while preserving evidence.

### 2.1 Snapshot evidence (do this BEFORE killing anything)

If you delete the pod first, you lose its filesystem and process state. Capture first.

```bash
# 1. Get the running pod's full spec
$ kubectl -n <ns> get pod <pod> -o yaml > /tmp/incident-pod-spec.yaml

# 2. Get pod logs (stderr + stdout)
$ kubectl -n <ns> logs <pod> --all-containers > /tmp/incident-pod-logs.txt
$ kubectl -n <ns> logs <pod> --all-containers --previous >> /tmp/incident-pod-logs.txt 2>/dev/null

# 3. Capture process tree inside the pod (if you can — may not work if attacker tampered)
$ kubectl -n <ns> exec <pod> -- ps auxf > /tmp/incident-pod-procs.txt 2>&1

# 4. Capture any files the attacker may have written
$ kubectl -n <ns> exec <pod> -- find /tmp /home /var/tmp -newer /etc/hostname -type f 2>/dev/null > /tmp/incident-pod-newfiles.txt

# 5. Note the pod's node — you may need it
$ NODE=$(kubectl -n <ns> get pod <pod> -o jsonpath='{.spec.nodeName}')
$ echo "Pod is on node: $NODE"
```

Move all `/tmp/incident-*` files to your evidence workspace.

### 2.2 Isolate the pod with a NetworkPolicy (don't kill it yet)

Killing the pod loses live state. A targeted NetworkPolicy stops the pod from talking to anything while keeping it alive for forensics.

```bash
$ cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: incident-quarantine-<incident-id>
  namespace: <ns>
spec:
  podSelector:
    matchLabels:
      <unique-label-from-pod>: <value>
  policyTypes:
    - Ingress
    - Egress
  # No rules — fully isolated
EOF
```

Verify the pod can no longer reach anything:

```bash
$ kubectl -n <ns> exec <pod> -- timeout 5 curl http://example.com
# expect: timeout
```

### 2.3 Rotate the credentials that may have been read

This is the most important step. If the attacker read `/root/.aws/credentials`, those keys must be considered compromised. Rotate immediately.

For an AWS access key:

```bash
# Identify the access key (the file's content, or your records)
$ aws iam list-access-keys --user-name <user> --profile <admin>

# Disable first (faster than delete; preserves CloudTrail correlation)
$ aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user> --profile <admin>

# Then delete
$ aws iam delete-access-key --access-key-id <key-id> --user-name <user> --profile <admin>
```

For a MinIO service account (the one Nextcloud uses):

```bash
$ mc admin user svcacct disable lab <access-key>
$ mc admin user svcacct rm lab <access-key>
```

Re-issue credentials and update the workload's Secret afterward (recovery phase).

### 2.4 Pull CloudTrail / audit-log activity for those credentials

Did the attacker actually use the credentials they read? Look at CloudTrail for the access key, or MinIO audit log for the MinIO key:

```bash
# AWS — last 60 minutes for that access key
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<key-id> \
    --start-time $(date -u -d '60 minutes ago' +%Y-%m-%dT%H:%M:%SZ) \
    --profile <admin> > /tmp/incident-cloudtrail.json
```

Look for:
- API calls from unusual source IPs (e.g., `sourceIPAddress` outside your office/VPC ranges)
- Calls outside the access key's normal pattern (does the workload normally use `iam:CreateAccessKey`? probably not)
- High-volume listing of resources (`s3:ListBucket`, `iam:ListRoles`) — suggests recon

If you see post-compromise API activity, **escalate to Critical and notify the IR coordinator.** Now you have a confirmed cloud breach, not just a host-level alert.

---

## 3. Eradication

Goal: remove the attacker's foothold and prevent re-entry by the same path.

### 3.1 Identify the entry vector

How did the attacker get into the container in the first place? Common causes:

- Vulnerability in the running app (check Phase 04 Trivy scan for HIGH/CRITICAL)
- Stolen kubectl credentials used to `kubectl exec` (check Kubernetes audit log)
- Compromised CI/CD pipeline pushing a backdoored image
- Exposed admin interface (check Ingress logs, MinIO access log)

Don't proceed to deletion until you have at least a hypothesis. Without it, you'll just kill the pod and the attacker will be back in 30 minutes via the same path.

### 3.2 Delete the pod

```bash
$ kubectl -n <ns> delete pod <pod>
```

If it's part of a Deployment / StatefulSet, a new pod will spin up. That's fine *if* you've patched the entry vector. If not, it'll be re-compromised — keep the quarantine NetworkPolicy in place until you have.

### 3.3 Patch

Specific to your hypothesis:

- **Vulnerable image** → rebuild from the latest base image, push to registry, redeploy
- **Stolen kubectl creds** → revoke the relevant kubeconfig, rotate any service-account tokens used, audit RBAC bindings
- **Bad CI/CD** → quarantine the pipeline, audit recent commits, rebuild from a known-good commit
- **Exposed interface** → fix the Ingress / Service / SG that exposed it

### 3.4 Hunt for related compromise

The reading of credentials is an early-stage technique. The attacker may have done more:

```bash
# Falco events from the same pod or namespace, last 6 hours
# In Kibana:
#   k8s.pod.name: "<pod>" OR k8s.ns.name: "<ns>"
# Time range: last 6 hours

# Other Falco rules that fired on the same node
#   k8s.node.name: "<node>" AND priority: ("Warning" OR "Critical")
```

Zeek / Suricata events from Security Onion — look for:
- Beacon-like traffic from any pod IP
- DNS queries for known C2 domains
- Outbound data volumes inconsistent with normal application traffic

If you find related events, broaden the incident scope.

---

## 4. Recovery

Goal: return to normal operation with confidence the attacker is out.

### 4.1 Redeploy the workload with new credentials

```bash
# Update the Secret with the rotated key
$ kubectl -n <ns> create secret generic <name> \
    --from-literal=access-key=<new-key> \
    --from-literal=secret-key=<new-secret> \
    --dry-run=client -o yaml | kubectl apply -f -

# Trigger a rollout
$ kubectl -n <ns> rollout restart deployment/<name>
$ kubectl -n <ns> rollout status deployment/<name>
```

### 4.2 Verify monitoring is still working

The attacker may have tried to disable Falco or tamper with logs:

```bash
$ kubectl -n security get pods   # falco pods all running?
$ kubectl -n security logs ds/falco --tail=20   # rules still loaded?

# Trigger a known-good detection to verify the pipeline end-to-end
$ kubectl run test-shell --image=alpine --restart=Never -- sleep 3600
$ kubectl exec -it test-shell -- sh
# Inside: just exit. The "shell in container" rule should fire.
$ kubectl delete pod test-shell

# Verify the alert appears in Sec Onion within 60 seconds
```

### 4.3 Remove the quarantine NetworkPolicy

Only after all of:
- Pod is deleted and replaced with a clean one
- Entry vector is patched
- Rotated credentials are deployed
- Monitoring verified

```bash
$ kubectl -n <ns> delete networkpolicy incident-quarantine-<incident-id>
```

### 4.4 Watch for 24 hours

Set a tighter Falco filter for this namespace for the next 24 hours. Any recurrence of the original alert, or related patterns, is treated as a new incident automatically.

---

## 5. Post-incident

Goal: make the next response faster.

### 5.1 Write the postmortem

A short doc with:
- Timeline (alert time → containment time → resolution time)
- Root cause
- What worked in the response
- What didn't
- Action items, each with an owner and due date

Save it. Even a homelab postmortem is something to point at in an interview.

### 5.2 Tune detections

If the alert was real, do you have detection earlier in the kill chain? For T1552.001, the read happens late — you'd ideally also detect:
- The shell that ran the read (T1059.004 — already covered by default Falco rule)
- The execution of the binary that started the shell (process-execution detection)
- The network access that delivered the binary (Suricata / Zeek)

Add the missing pieces or document the gap in `docs/09-attack-coverage.md`.

### 5.3 Update this runbook

Whatever surprised you during response — add it to the runbook. Runbooks live in version control for exactly this reason; every incident should produce a delta.

---

## Tabletop exercise (do this before your interview)

Walk through this runbook by simulating a detection in your own lab:

1. Trigger the alert (per Phase 05 step 4 testing)
2. Pretend it's a real incident
3. Execute the runbook end-to-end with a stopwatch
4. Time each phase
5. Note where you stalled or guessed

Write up the tabletop as `scans/ir-tabletop.md`. This is the artifact you point at when an interviewer asks "have you actually run a runbook end to end?" — yes, in a controlled environment, here's the writeup.

---

## What you can now talk about in an interview

- "I have a written runbook for one of my Falco detections — credential file read in a container, ATT&CK T1552.001. It walks an analyst from alert through containment, eradication, recovery, and postmortem with concrete commands at each step."
- "Containment before eradication. I quarantine via NetworkPolicy first to preserve the pod for forensics, capture evidence, then delete and patch."
- "The first thing I do on this alert isn't kill the pod — it's rotate the credentials that may have been read. Killing the pod doesn't help if the attacker already has the keys."
- "I tabletop my runbooks. There's a writeup of the dry run with timing for each phase."
- "Postmortems are mandatory, even for non-incidents. Each incident should produce updates to the runbook so the next response is faster."

## Repo complete

You've now got phases 02 through 10 plus a 09 ATT&CK matrix. That's the full lab. Day 5 is polish:
- Push everything to GitHub
- Pin a screenshot dashboard from Kibana to the README
- Print the ATT&CK matrix and the runbook for the panel
- Walk through your repo end-to-end as if presenting to the panel

Good luck.
