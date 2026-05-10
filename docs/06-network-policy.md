# Phase 06 — Network Policy (lite)

**Goal:** apply a default-deny NetworkPolicy in the `storage` namespace, then explicitly allow only the flows the lab needs. This forces you to explicitly enumerate every legitimate communication path — which is exactly what you'd do during a security architecture review.

**Time budget:** 1.5 hours.

**Note on scope:** the original phase 06 included swapping the k3s default CNI (Flannel) for Cilium and adding Hubble for observability. That's a destructive change requiring a cluster reset, which is unacceptable risk this close to your interview. You're doing the *lite* version: NetworkPolicy with the default CNI. You can talk about Cilium and eBPF networking in the panel without having migrated to it.

**You will end up with:**
- A `default-deny` NetworkPolicy applied to the `storage` namespace
- Explicit allow policies for: Nextcloud → Postgres, Nextcloud → MinIO, Ingress → Nextcloud
- A negative test (a pod in `default` blocked from reaching MinIO) saved as evidence

---

## Concepts

### NetworkPolicy is allow-listing for pods

By default, every pod in a Kubernetes cluster can talk to every other pod, regardless of namespace. NetworkPolicy lets you flip that to allow-listing: declare which traffic is allowed, and everything else is denied.

A NetworkPolicy resource selects pods (via labels) and declares:
- `policyTypes` — Ingress, Egress, or both
- `ingress` rules — what's allowed *into* the selected pods
- `egress` rules — what's allowed *out of* the selected pods

### Default-deny is the foundation

The pattern is:

1. Apply a "default-deny" policy that selects all pods in a namespace and allows nothing
2. Layer specific allow policies on top for each legitimate flow
3. Anything not explicitly allowed is denied

You don't *delete* allow rules to deny things — you simply don't add allow rules for them.

### Which CNI supports NetworkPolicy?

Not all CNIs do. k3s ships with **Flannel** by default, and Flannel does *not* support NetworkPolicy on its own — k3s adds a separate component (`kube-network-policies`, formerly `kube-router`) to make NetworkPolicy work with Flannel. As of recent k3s versions this is enabled by default, but verify:

```bash
$ kubectl get pods -n kube-system | grep -E "flannel|network-policies|kube-router"
```

If you see `kube-network-policies` or `kube-router`, NetworkPolicy works. If you see only flannel pods, you need to add policy enforcement, install Calico in policy-only mode, or accept that policies won't enforce. For Cilium / Calico CNIs, NetworkPolicy works natively.

### NetworkPolicy vs. Service Mesh

NetworkPolicy operates at L3/L4 (IPs and ports). It can't filter by HTTP method, header, or path. For L7 controls you need a service mesh (Istio, Linkerd) or Cilium's L7 policies. For most homelab and even most production scenarios, L3/L4 default-deny gets you 90% of the value.

---

## Prerequisites

- Phases 02 and 05 complete. Workloads in the `storage` and `security` namespaces are running.
- NetworkPolicy enforcement working in your cluster. Test:

```bash
$ kubectl get pods -n kube-system | grep -E "policies|router"
```

---

## Step 1 — Verify the current state (everything talks to everything)

```bash
# A throwaway pod in the default namespace
$ kubectl run probe --image=docker.io/library/curlimages/curl --restart=Never --rm -it -- sh

# Inside, prove you can reach MinIO from default namespace
~ $ curl -I http://minio.storage.svc.cluster.local:9000/
# returns HTTP 403 from MinIO (auth required) — meaning the connection succeeded
~ $ exit
```

You got a 403 from MinIO, which is what we want to *prevent*. The 403 means the network connection succeeded; MinIO just rejected the unauthenticated request. After applying NetworkPolicies, this connection shouldn't even establish.

---

## Step 2 — Apply default-deny

```bash
$ kubectl apply -f manifests/06-network/01-default-deny-storage.yaml
```

Read the file. It selects all pods in `storage` (`podSelector: {}` matches everything) and denies both ingress and egress (`policyTypes: [Ingress, Egress]` with no rules — empty means deny).

**This will break things.** Postgres and MinIO and Nextcloud now can't talk to each other or to the outside world. That's intentional. We'll add explicit allows in the next steps.

If you check Nextcloud's UI now, it will be unreachable. If you check `kubectl -n storage logs deployment/nextcloud`, you'll see DNS resolution failures (Nextcloud can't reach Postgres because the egress rules deny everything, including DNS).

---

## Step 3 — Allow DNS

Almost every legitimate workload needs DNS. The first allow rule:

```bash
$ kubectl apply -f manifests/06-network/02-allow-dns-storage.yaml
```

Read the file. It selects all pods in `storage` and allows egress to UDP/53 and TCP/53 to pods labeled `k8s-app=kube-dns` in `kube-system`. That's how CoreDNS is labeled.

After this is applied, DNS resolution works again but actual connections still don't.

---

## Step 4 — Allow Nextcloud → Postgres

```bash
$ kubectl apply -f manifests/06-network/03-allow-nextcloud-to-postgres.yaml
```

The policy:
- Selects pods labeled `app=postgres` (the Postgres pod)
- Allows ingress from pods labeled `app.kubernetes.io/name=nextcloud` on port 5432

Specificity matters. We're not allowing "anything in storage namespace to Postgres" — we're allowing "specifically Nextcloud pods on the Postgres port."

Verify Nextcloud → Postgres works:

```bash
$ kubectl -n storage logs deployment/nextcloud --tail=20
# Should not show DB connection errors anymore
```

---

## Step 5 — Allow Nextcloud → MinIO

```bash
$ kubectl apply -f manifests/06-network/04-allow-nextcloud-to-minio.yaml
```

Same shape: select MinIO pods, allow ingress from Nextcloud pods on port 9000.

Verify by uploading a file in the Nextcloud UI — it should succeed and land in MinIO.

---

## Step 6 — Allow Ingress controller → Nextcloud

The Traefik Ingress controller lives in `kube-system`. It needs to reach the Nextcloud pod on port 80 (or 443).

```bash
$ kubectl apply -f manifests/06-network/05-allow-ingress-to-nextcloud.yaml
```

The policy allows ingress to Nextcloud pods from the `kube-system` namespace (selected by namespace label).

Verify the Nextcloud UI is reachable again from your browser.

---

## Step 7 — Negative test (the evidence artifact)

Confirm the policies actually deny what they're supposed to deny:

```bash
# This should now FAIL (timeout) instead of returning 403
$ kubectl run probe --image=docker.io/library/curlimages/curl --restart=Never --rm -it -- sh
~ $ curl --max-time 5 -I http://minio.storage.svc.cluster.local:9000/
# expect: curl: (28) Connection timed out
```

Save the output to `scans/networkpolicy-deny-evidence.txt`. That's your proof that default-deny works.

Same test from a pod in `storage` but not Nextcloud:

```bash
$ kubectl run probe --image=docker.io/library/curlimages/curl --restart=Never -n storage --rm -it -- sh
~ $ curl --max-time 5 -I http://minio.storage.svc.cluster.local:9000/
# expect: timeout
```

This is more important than the cross-namespace test. It demonstrates that even *within* the same namespace, only labeled-Nextcloud pods can reach MinIO.

---

## Validation checklist

- [ ] `kubectl -n storage get networkpolicy` shows 5 policies
- [ ] Nextcloud UI loads from your browser
- [ ] Nextcloud → Postgres works (no DB errors in logs)
- [ ] Nextcloud → MinIO works (file upload succeeds and lands in bucket)
- [ ] A `curl` from a non-Nextcloud pod to MinIO times out
- [ ] You have `scans/networkpolicy-deny-evidence.txt` saved

---

## Troubleshooting

**Default-deny is applied but `curl` still works.** Your CNI doesn't enforce NetworkPolicy. Confirm with `kubectl get pods -n kube-system | grep -i policies`. If absent, you need to either install Calico in policy-only mode or accept that you can't complete this phase.

**Nextcloud can't reach Postgres after applying allow.** Label mismatch. The Nextcloud chart may use `app.kubernetes.io/name=nextcloud` but your selector might be `app=nextcloud`. Inspect actual labels: `kubectl -n storage get pods --show-labels`.

**Ingress to Nextcloud broken.** Traefik needs to reach the Nextcloud pod, but it lives in `kube-system`. Verify the kube-system namespace has the right label your policy selects on. If not, label it: `kubectl label ns kube-system kubernetes.io/metadata.name=kube-system` (it should be set by default in modern k8s).

**You're worried you broke something for phase 04 or phase 05.** Falco is in `security` namespace; these policies don't affect it. Gatekeeper is cluster-scoped; same. If you want to be safe, snapshot Proxmox before applying default-deny and you can roll back.

---

## What you can now talk about in an interview

- "I implemented default-deny NetworkPolicy in my storage namespace and explicitly allowed only the flows the application requires — Nextcloud to Postgres, Nextcloud to MinIO, and Ingress to Nextcloud. Anything else is dropped."
- "NetworkPolicy is L3/L4. For L7 controls I'd add a service mesh — Istio or Linkerd — or move to Cilium and use its L7 policies, which leverage eBPF."
- "I tested by negative — proving a non-Nextcloud pod can't reach MinIO confirms the policy is enforcing, not just present."
- "I know the trap with Flannel — it doesn't enforce NetworkPolicy on its own. k3s ships with a companion enforcer, but you can't assume that on every cluster."

## Next

Phase 07 — [Posture / hardening](07-posture-hardening.md). You'll run kube-bench (CIS Kubernetes Benchmark) and Kubescape (NSA framework) to baseline cluster posture and find remediations.
