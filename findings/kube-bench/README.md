# kube-bench Evidence

## Files

| File | Description |
|---|---|
| `kube-bench.txt` | Full CIS k3s-cis-1.7 benchmark output |
| `kube-bench-triage.md` | Finding categorization and rationale |

## Result summary

```
== Summary total ==
11 checks PASS
5 checks FAIL     ← all k3s false positives (see triage)
37 checks WARN
5 checks INFO
```

## How to regenerate

kube-bench must run directly on the control plane node (not as a Kubernetes Job —
the Job approach fails because Gatekeeper blocks pod creation in the default namespace
and the default job.yaml targets kubeadm paths that don't exist on k3s).

```bash
$ ssh ubuntu@<k3s-cp01-ip>
$ sudo /tmp/kube-bench --benchmark k3s-cis-1.7 --config-dir /tmp/cfg/ \
    2>&1 | tee /tmp/kube-bench.txt
$ exit
$ scp ubuntu@<k3s-cp01-ip>:/tmp/kube-bench.txt findings/kube-bench/kube-bench.txt
```

## Key finding: all 5 FAILs are k3s false positives

All failing checks are in section 4.2 (kubelet configuration). kube-bench checks
kubeadm-style paths (`/var/lib/kubelet/config.yaml`, kubelet process flags) that
do not exist in k3s. k3s embeds the kubelet as a goroutine and configures it
programmatically rather than via CLI flags.

Verification: port 10255 (kubelet read-only) confirmed closed. k3s already applies
secure kubelet defaults that kube-bench cannot verify through its standard mechanism.
