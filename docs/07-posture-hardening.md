# Phase 07 — Posture and Hardening

**Goal:** baseline your cluster's security posture using two industry-standard scanners — kube-bench (CIS Kubernetes Benchmark) and Kubescape (NSA + ArmoBest frameworks) — and produce a remediation plan from the findings.

**Time budget:** 1.5 hours. Most of this is reading the output, not running the tools.

**You will end up with:**
- A complete kube-bench report saved as `scans/kube-bench.txt`
- A Kubescape JSON report saved as `scans/kubescape.json`
- A summary remediation table tracking findings, severity, owner, and target fix date

---

## Concepts

### CIS Kubernetes Benchmark

The Center for Internet Security publishes prescriptive hardening guides for technologies — including Kubernetes. The CIS Kubernetes Benchmark is hundreds of specific configuration checks across:

- Control plane nodes (kube-apiserver, kube-controller-manager, kube-scheduler, etcd flags and file permissions)
- Worker nodes (kubelet config, kernel parameters, file permissions)
- Policies (RBAC, NetworkPolicy presence, Pod Security Standards usage, secret management)

For each check, the benchmark gives the rationale, the audit command, the expected result, and the remediation. **kube-bench** is an open-source scanner that runs the audit commands and reports pass/fail.

### NSA / CISA Kubernetes Hardening Guidance

The NSA published its own hardening guide focused on threat-driven recommendations rather than configuration checklists. **Kubescape** scans against the NSA framework (and a vendor-curated "ArmoBest" framework) — it checks similar things to kube-bench but also evaluates RBAC bindings, network policies, image vulnerabilities, and runtime misconfigurations together.

The two tools overlap but aren't redundant. kube-bench is more granular at the host/control-plane level; Kubescape is broader at the workload/policy level.

### Posture vs. compliance vs. detection

These often get conflated. Keep them separate:

- **Posture** — am I configured the way best practice says I should be? (kube-bench, Kubescape, CSPM tools)
- **Compliance** — am I configured the way a specific framework requires? (CIS, NIST, PCI, SOC 2 — partly the same checks, but mapped to control IDs and producing audit evidence)
- **Detection** — am I being attacked right now? (Falco, Suricata, GuardDuty)

A mature program does all three. Phase 05 covered detection. Phase 04 covered preventive admission. Phase 07 is posture/compliance.

---

## Prerequisites

- Phases 02, 04, 05 complete.
- `kubectl` from a cluster-admin context (kube-bench needs to read kubelet configs, kubescape needs to enumerate everything).
- SSH access to the control plane node (kube-bench runs there directly).

---

## Step 1 — kube-bench

> **Why not the Kubernetes Job approach:** the standard `kubectl apply -f job.yaml` approach fails on this setup for two reasons. First, the Job targets kubeadm binary paths (`/etc/kubernetes/`, `/usr/bin/kube-apiserver`) that don't exist on k3s — the scanner finds nothing to check. Second, Gatekeeper's `pods-require-resource-limits` constraint blocks pod creation in the `default` namespace, so the Job controller silently fails to schedule any pods and hangs indefinitely. Run kube-bench as a binary directly on the control plane node instead.

SSH into the control plane and run kube-bench there:

```bash
$ ssh ubuntu@<k3s-cp01-ip>

# Download the kube-bench binary
$ curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.9.4/kube-bench_0.9.4_linux_amd64.tar.gz \
    | tar -xz -C /tmp/

# Run against the k3s CIS benchmark (k3s uses different binary/config paths than kubeadm)
$ /tmp/kube-bench --benchmark k3s-cis-1.7 2>/dev/null | tee /tmp/kube-bench.txt

# Exit back to your workstation
$ exit

# Pull results back
$ mkdir -p scans
$ scp ubuntu@<k3s-cp01-ip>:/tmp/kube-bench.txt scans/kube-bench.txt

$ tail -30 scans/kube-bench.txt
# The summary at the bottom shows total PASS/FAIL/WARN counts per section
```

Open `scans/kube-bench.txt`. The output is structured as numbered sections (1.1.1, 1.1.2, ...) corresponding to CIS controls. Each line is `[PASS]`, `[FAIL]`, or `[WARN]`.

### What to do with the output

Don't aim for "all PASS." Many failures are intentional or impractical to fix in a homelab. Focus on:

1. **Filter to FAIL only** for the first pass:
```bash
$ grep '\[FAIL\]' scans/kube-bench.txt | wc -l
$ grep '\[FAIL\]' scans/kube-bench.txt | head -30
```

2. **Categorize each FAIL** as one of:
   - **Real risk** → schedule a fix
   - **Accepted risk for lab** → document why
   - **Not applicable** → CIS check is for a feature you don't use

3. **Pick 5 real-risk failures** and write remediation notes. Common ones in a fresh k3s cluster:
   - Anonymous auth enabled on kubelet (CIS 4.2.1) — disable in `--kubelet-config`
   - Audit logging not configured (CIS 1.2.18 / 1.2.19) — add `--audit-log-path` and `--audit-policy-file` to kube-apiserver
   - Default service accounts have tokens auto-mounted (CIS 5.1.5) — set `automountServiceAccountToken: false`
   - PSP / Pod Security Admission not enforced (CIS 5.2.x) — already done on `storage` namespace; expand to others

Save your categorization to `scans/kube-bench-triage.md`.

---

## Step 2 — Kubescape

Kubescape gives you a different angle, evaluating against frameworks rather than individual checks.

```bash
# Install kubescape on your workstation (WSL)
$ curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash
$ kubescape version
```

Run the NSA framework scan:

```bash
$ kubescape scan framework nsa --format json --output scans/kubescape-nsa.json
$ kubescape scan framework armobest --format json --output scans/kubescape-armobest.json

# Also produce a human-readable summary
$ kubescape scan framework nsa --format pretty-printer | tee scans/kubescape-nsa.txt
```

Look at the summary table at the bottom — it shows your "compliance score" per framework and the top failed controls.

### Cross-reference with kube-bench

Many findings overlap. Build a small comparison table:

```markdown
| Finding | kube-bench | Kubescape NSA | Severity | Action |
|---|---|---|---|---|
| Audit logging not enabled | 1.2.18 [FAIL] | C-0067 [Failed] | High | Configure k3s to write audit logs |
| Default SA token automounted | 5.1.5 [FAIL] | C-0034 [Failed] | Medium | Set automountServiceAccountToken: false on default SAs |
| ...etc | | | | |
```

When two tools agree, the finding is real. When only one flags something, dig into why — usually the other tool has it categorized differently or doesn't check it.

---

## Step 3 — Remediate one finding end-to-end

Don't try to fix everything. Pick one finding, fix it, re-scan, and document the before/after. This is the artifact that demonstrates remediation skill — going past surface-level findings.

A good first one: **automountServiceAccountToken on default ServiceAccounts**. Risk: any pod that doesn't specify a service account gets a token mounted that can be abused if the pod is compromised.

Fix:

```bash
$ for ns in default storage security; do
    kubectl patch serviceaccount default -n $ns \
      -p '{"automountServiceAccountToken": false}'
  done
```

Verify:

```bash
$ for ns in default storage security; do
    kubectl get sa default -n $ns -o jsonpath='{.metadata.name} {.automountServiceAccountToken}{"\n"}'
  done
# Should show "default false" for each
```

Re-run kube-bench and Kubescape, save as `scans/kube-bench-after.txt` and `scans/kubescape-nsa-after.json`. The relevant control should now PASS.

---

## Step 4 — Build a remediation tracker

Final artifact: a one-page tracker showing what's open, owner, and target.

```markdown
# Cluster Posture — Remediation Tracker

| ID | Source | Finding | Severity | Status | Owner | Target | Notes |
|---|---|---|---|---|---|---|---|
| 001 | kube-bench 1.2.18 | API server audit logging not configured | High | Open | me | Day 4 | Need to mount policy file into k3s |
| 002 | kube-bench 5.1.5 | Default SA tokens automount | Medium | **Closed** | me | Day 3 | Patched via kubectl |
| 003 | kubescape C-0067 | etcd encryption at rest not enabled | High | Open | me | Backlog | k3s defaults to no encryption — would require k3s reconfigure |
| ... | | | | | | | |
```

This tracker is the deliverable. Save as `scans/remediation-tracker.md` and reference it in your repo's main README.

---

## Validation checklist

- [ ] `scans/kube-bench.txt` exists and shows a section-by-section CIS report
- [ ] `scans/kubescape-nsa.json` and `scans/kubescape-armobest.json` exist
- [ ] You have `scans/kube-bench-triage.md` categorizing failures
- [ ] You have `scans/remediation-tracker.md` showing at least 5 findings
- [ ] At least one finding is actually remediated and verified by re-scan
- [ ] Before-and-after evidence saved (`*-after.*` files)

---

## Key takeaways

- Ran the CIS Kubernetes Benchmark via kube-bench and the NSA framework via Kubescape. They overlap on most things but not all — both are useful, neither is sufficient alone.
- 100% PASS on CIS is rarely the right goal — some checks are inappropriate for the architecture. Failures categorize into real-risk, accepted-risk, or not-applicable; prioritization works on real-risk first.
- One finding remediated end-to-end, with before/after evidence. The pattern repeats for the rest of the open findings — the missing piece in a lab vs production is change-management process around each fix.
- Posture is about being configured correctly. Detection (Phase 05's Falco work) is about catching the cases where configuration alone wasn't enough. Both layers matter.

## Next

Phase 08 — [CSPM lite](08-cspm-lite.md). You'll deploy three deliberate misconfigurations in AWS, scan them with Prowler, and remediate. This is the "you've worked with cloud-native CSPM" artifact.
