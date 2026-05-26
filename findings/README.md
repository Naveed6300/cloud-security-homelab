# Lab Findings

Evidence from security scanning tools run against the k3s homelab cluster.
Each subdirectory contains raw tool output and any screenshots captured during the lab.

## Structure

```
findings/
├── remediation-tracker.md    ← master finding register with status
├── trivy/                    ← image and cluster vulnerability scans
├── falco/                    ← runtime detection alerts and screenshots
├── kube-bench/               ← CIS Kubernetes Benchmark results
└── kubescape/                ← NSA and ArmoBest framework scan results
```

## Scan Summary

| Tool | Framework | Score / Result | Date |
|---|---|---|---|
| kube-bench v0.9.4 | CIS k3s-cis-1.7 | 11 PASS / 5 FAIL / 37 WARN | 2026-05-25 |
| Kubescape v4.0.8 | NSA | 57.64% | 2026-05-25 |
| Kubescape v4.0.8 | ArmoBest | 62.91% | 2026-05-25 |
| Trivy | CVE + Misconfig | See trivy/ | 2026-05-10 |
| Falco | Runtime Detection | 4 rules triggered | 2026-05-17 |

## Key Notes

- **kube-bench FAIL findings are k3s false positives.** All 5 failures are in section 4.2
  (kubelet configuration). kube-bench checks kubeadm-style paths that don't exist in k3s.
  Port 10255 is confirmed closed; k3s applies secure kubelet defaults internally.

- **Privileged container findings (Falco, Longhorn) are accepted risk.** Falco requires
  privileged for eBPF kernel access. Longhorn requires it for block device management.
  Both are explicitly exempted in the phase 04 Gatekeeper constraints with documented rationale.

- **Image signature findings (C-0237, 8% compliance) are lab scope.** Cosign/sigstore
  pipeline is a future phase item. The registry allowlist from phase 04 partially mitigates
  by restricting pull sources.

See `remediation-tracker.md` for the full finding register with status and triage decisions.
