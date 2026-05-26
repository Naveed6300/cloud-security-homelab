# Kubescape Evidence

## Files

| File | Description |
|---|---|
| `kubescape-nsa.txt` | NSA framework scan — pretty-printer output |
| `kubescape-armobest.txt` | ArmoBest framework scan — pretty-printer output |

## Result summary

| Framework | Controls | Passed | Failed | Score |
|---|---|---|---|---|
| NSA | 26 | 7 | 14 | **57.64%** |
| ArmoBest | 39 | 14 | 18 | **62.91%** |

## Top failing controls (by resource count)

| Control | ID | Failed | Score |
|---|---|---|---|
| Automatic mapping of service account | C-0034 | 24 | 72% → **Remediated (F-001)** |
| Ingress and Egress blocked | C-0030 | 21 | 36% |
| Non-root containers | C-0013 | 20 | 23% |
| Linux hardening | C-0055 | 19 | 27% |
| Allow privilege escalation | C-0016 | 19 | 27% |
| CPU limits | C-0270 | 18 | 31% |
| Image signatures | C-0237 | 24 | 8% |

## How to regenerate

```bash
# Install
$ curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash
$ export PATH=$PATH:/home/$USER/.kubescape/bin

# Scan
$ kubescape scan framework nsa --format pretty-printer | tee findings/kubescape/kubescape-nsa.txt
$ kubescape scan framework armobest --format pretty-printer | tee findings/kubescape/kubescape-armobest.txt
```

## Notes

- "Action Required" items (audit logs, etcd encryption, kubelet checks) require the
  Kubescape operator to scan properly — the CLI cannot check these without node-level access
- Image signature control (C-0237) shows 8% — this is expected since cosign is not configured
  in this lab
- Longhorn and Falco privileged container findings are accepted risk — see remediation tracker
