# Phase 04 — Supply Chain Security

**Goal:** scan the images you deployed in phase 02 for known vulnerabilities, then layer in OPA Gatekeeper to enforce policies at admission time so future bad pods never get into the cluster.

**Time budget:** 3 hours. The Trivy work is fast; Gatekeeper takes longer because writing your first policy requires reading some Rego.

**You will end up with:**
- Trivy scan reports for every image running in the cluster
- An understanding of which CVEs to actually care about and which to defer
- OPA Gatekeeper installed and enforcing three policies
- A test harness that demonstrates the policies blocking bad workloads

**Note: cosign is deferred.** The original phase 04 plan included sigstore/cosign for image signing and verifying signed images at admission. It's deferred for scope reasons — image signing is a strong signal but takes meaningful time to wire up, and Trivy + Gatekeeper covers most of the supply-chain story. Cosign and SLSA are documented as next steps in the roadmap.

---

## Concepts

### What "supply chain" means in container security

When you `docker pull nextcloud:30-apache`, you're trusting a long chain:

1. The Nextcloud project's developers committing code
2. Their CI building an image and pushing it to Docker Hub
3. The image including base layers (Debian, PHP, Apache) maintained by other people
4. Each of those base layers including OS packages from distro repos
5. PHP and Apache including third-party libraries

A vulnerability anywhere in that chain becomes your problem the moment the image runs in your cluster. Supply chain security is the practice of (a) knowing what's in your images, (b) policing what's allowed to enter the cluster, and (c) verifying integrity end to end.

### Static scanning vs. runtime detection

- **Static scanning (Trivy)** examines an image *before* it runs. It looks at the filesystem layers and asks: which OS packages are installed, which library versions, are any of them associated with known CVEs?
- **Runtime detection (Falco, phase 05)** watches the image *while* it runs. It can catch behavior the static scanner can't predict (a containerized process spawning a shell, reading `/etc/shadow`, making unexpected outbound connections).

Both layers matter. A static scan tells you the image *contains* a known-vulnerable version of `glibc`. Runtime detection tells you something *exploited* it. You need both.

### CVE severity and the danger of treating it as a number

Every CVE has a CVSS score (0.0–10.0). Tools love it because it produces a clean "HIGH/CRITICAL" filter. Reality is messier:

- A CRITICAL CVE in a parser library *only used to read trusted input* is much less risky than a MEDIUM CVE in an internet-facing handler.
- A CVE marked "Disputed" by the maintainer may be misleading.
- A CVE in a binary you don't actually call (the package is installed but the vulnerable function is never invoked) doesn't matter much.

In practice: filter by severity to triage, but always look at *exposure* and *reachability* before declaring a finding actionable. This is the answer to the recurring "you have 2,000 findings on Monday morning, what do you do first?" question — it's about applying judgment, not raw counts.

### Admission controllers

Kubernetes has a pluggable admission system. When you `kubectl apply` something, the API server runs the request through a chain of admission controllers before persisting it. Two flavors:

- **Validating** — say "yes/no" without modifying the request. Reject the pod, or let it through.
- **Mutating** — modify the request before it's persisted. Inject a sidecar, set a default annotation.

OPA Gatekeeper is a *validating* admission webhook. You write policies in **Rego** (OPA's policy language), Gatekeeper evaluates them against incoming requests, and rejects anything that violates.

### Why Gatekeeper over Kyverno or Pod Security Admission?

Three options for admission control on Kubernetes:

| Tool | Strengths | Trade-offs |
|---|---|---|
| Pod Security Admission (built-in) | No install, three preset levels (privileged/baseline/restricted), works at namespace scope | Coarse — only enforces Pod Security Standards, can't write custom rules |
| OPA Gatekeeper | Rego language is powerful and standard, large policy library, used widely in industry | Rego has a learning curve |
| Kyverno | YAML policies, easier to read, more "Kubernetes-native" syntax | Smaller ecosystem; less common in large enterprises |

For this lab, Gatekeeper is the better choice — it's what most large enterprises run, and Rego transfers directly to OPA used in CI/CD policy gates.

You're already using Pod Security Admission (the `baseline` label on the `storage` namespace from phase 02). Gatekeeper layers *additional* custom rules on top.

---

## Prerequisites

- Phase 02 complete. Nextcloud and MinIO are running in the `storage` namespace.
- Trivy installed on your workstation (the `aquasecurity/trivy` apt repo, or via `apt install trivy`).
- Cluster admin permissions (you'll be installing Gatekeeper which adds CRDs and a webhook).

```bash
$ trivy --version
$ kubectl auth can-i create clusterroles -n kube-system
# should return "yes"
```

---

## Step 1 — Inventory images in the cluster

Before scanning anything, know what you're scanning. Capture the list of every image currently running:

```bash
$ kubectl get pods -A -o jsonpath="{range .items[*]}{range .spec.containers[*]}{.image}{'\n'}{end}{end}" | sort -u
```

Save this list to `scans/cluster-images.txt`. You should see:

- `postgres:16-alpine`
- `quay.io/minio/minio:RELEASE.<date>` (or similar)
- `docker.io/library/nextcloud:30-apache`
- `traefik:<version>` (k3s default Ingress controller)
- A handful of k3s system images (CoreDNS, local-path-provisioner, metrics-server)

This list is itself a security artifact. In a real environment, the inventory would feed into a CMDB or a CSPM that tracks "where is each image deployed and where does it come from?"

---

## Step 2 — Scan the cluster with Trivy

`trivy k8s` does scanning across your cluster — it pulls the running image references, scans each, and aggregates.

```bash
$ mkdir -p scans
$ trivy k8s --report summary cluster
```

You'll see a table with namespaces and severity counts. Now generate a detailed report you can dig into:

```bash
$ trivy k8s --report all --severity HIGH,CRITICAL --format json cluster > scans/k8s-trivy.json
$ trivy k8s --report all --severity HIGH,CRITICAL --format table cluster > scans/k8s-trivy.txt
```

Skim the table report. Notice:

- Most findings will be in the Nextcloud and MinIO base images. That's expected — application stacks accumulate CVEs.
- Some findings will be in `traefik` and the k3s system images. These come "for free" with k3s and are out of your direct control.
- The report shows the **fixed version** for each CVE. That tells you whether remediation is "rebuild from a newer base" (easy) or "wait for upstream" (hard).

### Interpret three findings yourself

Pick three findings from `scans/k8s-trivy.txt` and write a one-line triage in `scans/triage.md`:

```markdown
| Finding | Severity | Image | Reachable? | Action |
|---|---|---|---|---|
| CVE-202X-XXXX | CRITICAL | nextcloud:30-apache | Yes — apache faces the Internet | Update base image when 30.1 ships |
| CVE-202X-YYYY | HIGH | postgres:16-alpine | No — DB is cluster-internal only | Defer; monitor for fix |
| CVE-202X-ZZZZ | HIGH | minio:RELEASE.* | Partial — Console exposed | Rebuild on next MinIO release |
```

This is the deliverable that demonstrates triage skill — applying judgment over a CVE finding, not just reading a tool.

---

## Step 3 — Scan a single image deeply

`trivy k8s` is a high-level overview. `trivy image` gives you the full breakdown for one image, including secrets and misconfigurations:

```bash
$ trivy image --severity HIGH,CRITICAL --scanners vuln,secret,misconfig nextcloud:30-apache | tee scans/nextcloud-image.txt
```

The `--scanners` flag controls what Trivy looks for:
- **vuln** — package CVEs
- **secret** — hard-coded secrets in the image (API keys, passwords)
- **misconfig** — Dockerfile and config-file issues (running as root, latest tag usage, etc.)

Pay attention to any secret findings. Hardcoded credentials in published images are the supply-chain failure that most often makes the news.

---

## Step 4 — Install OPA Gatekeeper

```bash
$ helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
$ helm repo update

$ helm install gatekeeper gatekeeper/gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace \
    --set replicas=1 \
    --set auditInterval=60
```

The install adds:
- A `gatekeeper-system` namespace
- A controller-manager Deployment
- A ValidatingWebhookConfiguration that intercepts `kubectl apply` for most resource types
- CRDs: `ConstraintTemplate`, and constraint kinds you'll define

Wait for it to roll out:

```bash
$ kubectl -n gatekeeper-system rollout status deployment/gatekeeper-audit
$ kubectl -n gatekeeper-system rollout status deployment/gatekeeper-controller-manager
$ kubectl -n gatekeeper-system get pods
```

### Concept break — Gatekeeper's two-step model

Gatekeeper policies have two pieces:

1. **ConstraintTemplate** — a reusable policy *definition*. Written in Rego. Defines what rule shape is being enforced (e.g., "block containers that do X").
2. **Constraint** — an *instantiation* of a template, scoped to specific resources. Says "apply this rule to Pods in these namespaces with these parameters."

The split lets you write a template once and apply it many times with different parameters.

---

## Step 5 — Policy 1: Block privileged containers

This duplicates what Pod Security Admission `baseline` already enforces at the namespace level — by design. You're learning the Gatekeeper pattern with a known-safe policy first.

Apply both files in `manifests/04-supply-chain/`:

```bash
$ kubectl apply -f manifests/04-supply-chain/01-privileged-template.yaml
$ kubectl apply -f manifests/04-supply-chain/01-privileged-constraint.yaml
```

Read both files. The template is the interesting one — it's where the Rego lives.

```rego
violation[{"msg": msg}] {
  c := input.review.object.spec.containers[_]
  c.securityContext.privileged == true
  msg := sprintf("Privileged container '%v' not allowed", [c.name])
}
```

In English: for every container in the incoming pod spec, if `securityContext.privileged == true`, produce a violation message.

Test it. This should be **rejected** by the webhook:

```bash
$ kubectl run priv-test --image=busybox --restart=Never \
    --overrides='{"spec":{"containers":[{"name":"test","image":"busybox","securityContext":{"privileged":true}}]}}'
# Error from server (Forbidden): admission webhook "validation.gatekeeper.sh" denied the request:
# [pod-deny-privileged] Privileged container 'test' not allowed
```

Save the rejection error to `scans/gatekeeper-privileged-rejection.txt` as evidence the policy is enforcing.

---

## Step 6 — Policy 2: Require resource limits

This one Pod Security Admission can't do — it's a custom rule. We require every container to have CPU and memory limits set. Without limits, a runaway container can consume the whole node.

```bash
$ kubectl apply -f manifests/04-supply-chain/02-resource-limits-template.yaml
$ kubectl apply -f manifests/04-supply-chain/02-resource-limits-constraint.yaml
```

Inspect the constraint — it scopes itself to the `storage` and `default` namespaces and selects only Pods. We don't want it to fight with system pods in `kube-system` that may legitimately not have limits.

Test:

```bash
$ kubectl run nolimit --image=nginx --restart=Never -n default
# rejected
```

Now make sure your existing storage-namespace workloads are compliant. If you used the values files in `manifests/02-storage/`, they have limits set. If you tweaked things, update them now — Gatekeeper has an **audit** mode that reports existing violations:

```bash
$ kubectl get k8srequiredresourcelimits -o yaml
# look at status.violations
```

This tells you which existing pods would fail the policy if they were re-admitted. In production, you'd remediate these before turning on enforcement.

---

## Step 7 — Policy 3: Restrict allowed image registries

The strongest supply-chain control. Only allow images from registries you trust (Docker Hub library, your private registry, the chart-vendor registries you actively use).

```bash
$ kubectl apply -f manifests/04-supply-chain/03-allowed-registries-template.yaml
$ kubectl apply -f manifests/04-supply-chain/03-allowed-registries-constraint.yaml
```

The constraint specifies an allowed list:

```yaml
parameters:
  registries:
    - "docker.io/library/"
    - "docker.io/nextcloud/"
    - "quay.io/minio/"
    - "registry.k8s.io/"
    - "rancher/"
    - "openpolicyagent/"
    - "falcosecurity/"
```

Test by trying to deploy an image from an unlisted registry:

```bash
$ kubectl run shady --image=ghcr.io/random/random:latest --restart=Never -n default
# rejected
```

This is one of the most impactful policies in practice — it directly addresses "how do you prevent a developer from accidentally deploying an untrusted image?"

---

## Step 8 — Audit existing workloads

Gatekeeper doesn't just block new admissions — it audits existing resources too. Run an audit summary:

```bash
$ for c in K8sPSPPrivilegedContainer K8sRequiredResourceLimits K8sAllowedRepos; do
    echo "=== $c ==="
    kubectl get $c -o jsonpath="{.items[*].status.violations}" | jq
  done > scans/gatekeeper-audit.json
```

Save the audit. If you see violations, decide: is the policy wrong, or is the workload wrong?

---

## Validation checklist

- [ ] `trivy k8s` produces a report with HIGH/CRITICAL findings categorized by namespace
- [ ] You have a `scans/triage.md` with at least 3 findings triaged with "reachable?" and "action"
- [ ] Gatekeeper is healthy: `kubectl -n gatekeeper-system get pods` shows controller and audit pods Running
- [ ] All 3 ConstraintTemplates exist: `kubectl get constrainttemplates` shows 3 entries
- [ ] All 3 Constraints exist and have `enforced: true` status
- [ ] You have evidence files: `gatekeeper-privileged-rejection.txt`, `gatekeeper-audit.json`
- [ ] None of your phase-02 workloads are violating any policy

---

## Troubleshooting

**Trivy DB download fails behind a proxy.** `trivy --skip-db-update` will use whatever local DB it has, but you need to update it once. Set `TRIVY_DB_REPOSITORY` to a mirror or run `trivy image --download-db-only` while connected.

**Gatekeeper webhook timing out and pods getting stuck in admission.** The webhook has a 3-second default. If the controller is slow (cold start, low resources), legitimate admissions fail. Check `kubectl -n gatekeeper-system logs -l control-plane=controller-manager`. Bump the controller's resources if needed.

**Constraint is created but not enforced.** Check `kubectl describe <constraint>`. The `status.byPod` field shows whether each Gatekeeper pod has loaded the constraint. If not, restart the controllers.

**Existing violations on system pods.** Gatekeeper audits cluster-wide by default. To exclude `kube-system` from a constraint's scope, edit the `match.namespaces` field to omit it, or use `match.excludedNamespaces`. The Constraints in `manifests/04-supply-chain/` already do this.

**Policy works but feels brittle.** That's because you're writing per-rule Rego. The OPA community publishes a [Gatekeeper Library](https://github.com/open-policy-agent/gatekeeper-library) of pre-written templates. For phase 04 we're writing them by hand to learn; in production you'd reuse the library.

---

## Key takeaways

- Trivy scans every image entering the cluster; findings are triaged by severity, exposure, and reachability — not severity alone.
- OPA Gatekeeper enforces supply-chain policies at admission time. Custom Rego constraints block privileged containers, require resource limits, and restrict the registries images can pull from.
- Pod Security Standards handle the obvious cases at the namespace level. Gatekeeper layers custom Rego policies on top for organization-specific rules.
- Admission control vs. runtime detection: admission catches misconfigurations *before* they run, runtime catches malicious behavior at execution. Phase 05 adds Falco for the runtime layer.
- Cosign and image signing are the next layer above scanning — verifying provenance, not just contents. Documented in the roadmap.

## Next

Phase 05 — [Runtime security](05-runtime-security.md). You'll deploy Falco, trigger detections, and forward alerts to your existing Security Onion deployment for centralized visibility.
