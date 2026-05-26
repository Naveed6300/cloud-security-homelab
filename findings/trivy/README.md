# Trivy Scan Evidence

## Files

| File | Description |
|---|---|
| `trivy-k8s-summary.txt` | Cluster-wide scan summary — `trivy k8s --report summary --severity HIGH,CRITICAL` |
| `k8s-trivy.json` | Full JSON output for programmatic processing |
| `gatekeeper-audit.json` | Gatekeeper audit output showing constraint violations at time of scan |
| `cluster-images.txt` | List of all container images running in the cluster |

## How to regenerate

```bash
$ trivy k8s --report summary --severity HIGH,CRITICAL | tee findings/trivy/trivy-k8s-summary.txt
$ trivy k8s --report all --severity HIGH,CRITICAL --format json > findings/trivy/k8s-trivy.json
```

## Triage approach

Filter by severity then narrow by exposure:
1. Is the vulnerable package actually loaded by the running application?
2. Is the workload internet-facing (via Ingress) or internal-only?
3. Does a fixed version exist upstream?

A HIGH CVE in a package that's never called and on an internal-only service is lower priority
than a CRITICAL CVE in the HTTP parsing layer of an internet-facing Nextcloud.
