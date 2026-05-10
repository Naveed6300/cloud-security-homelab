# Phase 02 — Storage Workload

**Goal:** deploy MinIO (S3-compatible object storage), Postgres (Nextcloud's metadata DB), and Nextcloud (the file-sync UI), with Nextcloud configured to use MinIO as its primary object backend. By the end, you'll log into Nextcloud from a browser, upload a file, and see it land as an object in a MinIO bucket.

**Time budget:** 2–3 hours. If it stretches past 4, stop and check the troubleshooting section — you've probably hit one of the common issues.

**You will end up with:**
- Three workloads running in a `storage` namespace
- Nextcloud reachable via Ingress at a hostname you control
- A MinIO bucket holding actual file data
- A Postgres instance holding Nextcloud metadata (user accounts, file index, sharing tables)
- Manifests committed to your repo so the deploy is reproducible

---

## Concepts

You're going to deploy three things that talk to each other. Before you do, understand each one in isolation and then how they compose.

### Why object storage instead of just files on disk?

Object storage exposes data through HTTP APIs (PUT, GET, DELETE on URLs) rather than POSIX filesystem calls (`open()`, `read()`, `write()`). The two have different design centers. Filesystems optimize for low-latency random-access reads inside a single host. Object storage optimizes for massive scale, durability across failure domains, and stateless horizontal access from many clients at once.

Cloud storage is built almost entirely on object stores. AWS S3, Azure Blob, GCS — all object stores at the bottom. So if you understand the object-storage model — buckets, keys, prefixes, ACLs, signed URLs, server-side encryption, versioning, lifecycle rules, replication — you understand the substrate that most cloud security work sits on top of. **MinIO is fully S3-API-compatible**, so every concept you exercise against MinIO transfers directly to S3, Azure (via S3 API gateways), or GCS.

This is the highest-leverage component in the lab. If you only learn one thing from phase 02, learn how object stores actually behave.

### Why Nextcloud on top of MinIO?

MinIO alone is just an empty store. Nextcloud is the user-facing application — login screen, file browser, share links, sync clients — that gives you something realistic to attack and defend in later phases. Phase 04 (admission control), phase 05 (runtime detection), phase 06 (network policy) all use Nextcloud and MinIO as the targets they're protecting.

Nextcloud has two storage modes: it can store files on a local filesystem (the default, easy but not how real cloud apps work) or in an "external" S3-compatible backend with all primary file data in object storage and metadata in a relational DB. We use the second mode because that's how production cloud apps are built — separating metadata (relational DB) from primary object data (S3-compatible store) is the canonical architecture.

### Why Postgres?

Nextcloud needs a database for its metadata: user accounts, file→object mappings, shares, calendar events, audit log entries. By default it falls back to SQLite, which is fine for one-user toy installs but doesn't survive concurrent access well. Postgres is the production-grade choice for any real Nextcloud deployment, and using it here teaches you how stateful apps are usually wired in Kubernetes (StatefulSet + PVC + Service).

### Kubernetes storage primitives

You'll see these in every manifest. Internalize them now.

- **PersistentVolume (PV)** — a piece of storage in the cluster. Could be a directory on a node's local disk, a network share, an EBS volume, anything.
- **PersistentVolumeClaim (PVC)** — a workload's *request* for storage. "I need 10 GiB of ReadWriteOnce storage." The cluster matches the PVC to a PV.
- **StorageClass** — describes *how* to provision a PV when a PVC is created. The `local-path` class that ships with k3s creates a PV by making a directory on whichever node the pod lands on.
- **Access modes** — `ReadWriteOnce` (one node can mount r/w), `ReadOnlyMany` (many can mount r/o), `ReadWriteMany` (many can mount r/w; rare and storage-driver-specific).
- **Reclaim policy** — what happens to the PV when its PVC is deleted. `Retain` keeps the data and requires manual cleanup. `Delete` deletes the data. **Security implication**: if a PVC holds sensitive data, your reclaim policy determines whether `kubectl delete pvc` securely sanitizes the underlying disk. For most cloud block storage, `Delete` triggers driver-level erase; for `local-path`, it just removes the directory.

For this lab, k3s's built-in `local-path` provisioner is fine — it stores PVs under `/var/lib/rancher/k3s/storage/` on the node where the pod runs. The downside is that if a worker node dies, pods scheduled there can't be rescheduled elsewhere because the PV is local. In a real environment you'd use Longhorn, Ceph, EBS-CSI, or similar. For 4 days of lab work, accept the limitation.

### Namespaces and why they matter

A namespace is a logical partition of the cluster. Resources in different namespaces can't see each other by default for things like ConfigMaps and Secrets. **For security**, namespaces matter because they're the boundary unit for:
- RBAC (Role bindings can be namespace-scoped)
- NetworkPolicy (most policies select pods within a namespace)
- ResourceQuota (caps on CPU/memory/storage per namespace)
- Pod Security Standards (enforced per-namespace)

We'll use a `storage` namespace for everything in this phase. In phase 05 you'll add a `security` namespace for Falco and Gatekeeper. In phase 06 you'll write NetworkPolicies that lean on the namespace boundary.

### Helm in 30 seconds

Helm is the package manager for Kubernetes. A Helm "chart" is a templated bundle of manifests with a `values.yaml` that lets you override defaults. Instead of writing 800 lines of YAML for a Postgres deployment, you `helm install postgres bitnami/postgresql -f my-values.yaml` and the chart renders the manifests from your overrides.

You'll use Helm for MinIO and Nextcloud because both have well-maintained charts. Postgres can be a one-off Bitnami chart, but for transparency we'll deploy it from raw manifests so you see every line.

---

## Prerequisites

- Phase 01 complete. `kubectl get nodes` from your workstation shows three Ready nodes.
- Helm installed on your workstation. If you haven't (or you're recovering from the baltocdn migration noted in the install guide):

```bash
$ curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-4 | bash
$ helm version
```

- A way to reach Ingress hostnames from your workstation. The simplest path: edit `/etc/hosts` on your workstation to map your chosen hostname to one of the cluster node IPs. We'll use `nextcloud.lab.internal` and `minio.lab.internal` throughout this doc.

```bash
# On your workstation, add to /etc/hosts:
$ sudo sh -c 'echo "10.10.20.201  nextcloud.lab.internal minio.lab.internal" >> /etc/hosts'
# replace 10.10.20.201 with one of your k3s node IPs
```

---

## Step 1 — Create the namespace

The first concrete thing you do is partition the cluster.

```bash
$ kubectl apply -f manifests/02-storage/namespaces.yaml
$ kubectl get ns storage
```

Open `manifests/02-storage/namespaces.yaml` and read it before applying — it's three lines and worth understanding:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: storage
  labels:
    purpose: storage
    pod-security.kubernetes.io/enforce: baseline
```

The `pod-security.kubernetes.io/enforce: baseline` label activates Kubernetes's built-in Pod Security Standards on this namespace. There are three levels:

- **privileged** — wide-open, anything goes
- **baseline** — blocks the most-known-bad things (privileged containers, hostPath mounts, host networking, hostPID/hostIPC)
- **restricted** — blocks much more (must run as non-root, drop capabilities, seccomp required, etc.)

We start with `baseline` because Nextcloud and MinIO charts won't deploy under `restricted` without significant tweaking. Phase 04 is where we'll layer OPA Gatekeeper for finer-grained admission control.

**Validation:** `kubectl get ns storage` shows `Active`. `kubectl get ns storage -o yaml | grep enforce` shows the label.

---

## Step 2 — Deploy Postgres

Why we start with Postgres: Nextcloud's bootstrap process tries to connect to its database immediately on first launch. If Postgres isn't ready, Nextcloud fails initialization and you waste time debugging Nextcloud when the real issue is upstream. Always deploy stateful dependencies first.

Read `manifests/02-storage/postgres.yaml`. It defines:

1. A **Secret** holding the Postgres superuser password and the Nextcloud user password. (You'll generate these — never commit real values.)
2. A **PersistentVolumeClaim** for the data directory.
3. A **StatefulSet** with one replica running the `postgres:16-alpine` image.
4. A **Service** of type `ClusterIP` so Nextcloud can resolve `postgres.storage.svc.cluster.local`.

Generate two random passwords and write them into a local Secret manifest. **Do not commit this file** — `.gitignore` already excludes `*-secrets.yaml`:

```bash
$ POSTGRES_PASSWORD=$(openssl rand -base64 24)
$ NEXTCLOUD_DB_PASSWORD=$(openssl rand -base64 24)

$ cat <<EOF > manifests/02-storage/postgres-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: postgres-credentials
  namespace: storage
type: Opaque
stringData:
  postgres-password: "${POSTGRES_PASSWORD}"
  nextcloud-db-password: "${NEXTCLOUD_DB_PASSWORD}"
EOF

$ kubectl apply -f manifests/02-storage/postgres-secrets.yaml
$ kubectl apply -f manifests/02-storage/postgres.yaml
```

Save those two passwords somewhere safe (your password manager). You'll need `NEXTCLOUD_DB_PASSWORD` again in step 4.

Watch Postgres come up:

```bash
$ kubectl -n storage get pods -w
# wait for postgres-0 to be 1/1 Running

$ kubectl -n storage logs postgres-0
# look for "database system is ready to accept connections"
```

**Validation:** Run a one-off psql client pod and connect:

```bash
$ kubectl -n storage run pg-client --rm -it --image=postgres:16-alpine \
    --restart=Never -- psql -h postgres -U postgres
# enter the postgres-password when prompted
# at the postgres=# prompt:
\l
\q
```

You should see the default database list and exit cleanly.

**Concept check:** What was the role of the StatefulSet vs. a Deployment for Postgres? StatefulSets give pods stable network identities (`postgres-0`, `postgres-1`) and stable PVC bindings (each replica gets its own PVC named `data-postgres-0`, `data-postgres-1`). For databases, that stability matters — you can't have postgres-0's PVC accidentally migrate to a pod called postgres-newhash-xyz on restart. Deployments are for stateless workloads.

---

## Step 3 — Deploy MinIO

MinIO is the object store. We'll install it with the official Helm chart.

```bash
$ helm repo add minio https://charts.min.io/
$ helm repo update
```

Open `manifests/02-storage/minio-values.yaml` and read every line. Important configuration choices:

- `mode: standalone` — single replica. MinIO supports `distributed` mode with 4+ replicas for erasure coding, but standalone is fine for the lab.
- `persistence.size: 20Gi` — the data volume. Pick something your cluster can satisfy.
- `rootUser` and `rootPassword` — the equivalent of AWS root keys. Never use these from applications; create a per-app service account.
- `ingress.enabled: true` — exposes the MinIO Console (web UI) at `minio.lab.internal`.
- `resources.requests.memory: 512Mi` — MinIO is memory-hungry; 512Mi is the practical floor.

Generate MinIO root credentials and write them to a local override (gitignored):

```bash
$ MINIO_ROOT_USER=admin
$ MINIO_ROOT_PASSWORD=$(openssl rand -base64 24)

$ cat <<EOF > manifests/02-storage/minio-secrets.yaml
# Local override — DO NOT COMMIT
rootUser: "${MINIO_ROOT_USER}"
rootPassword: "${MINIO_ROOT_PASSWORD}"
EOF

$ helm install minio minio/minio \
    --namespace storage \
    -f manifests/02-storage/minio-values.yaml \
    -f manifests/02-storage/minio-secrets.yaml
```

Watch the rollout:

```bash
$ kubectl -n storage rollout status deployment/minio
$ kubectl -n storage get pods -l app=minio
```

Open the MinIO Console at `http://minio.lab.internal:9001` (or whatever NodePort/Ingress mapping you set) and log in with the root credentials. **You should see an empty server with zero buckets.**

### Step 3a — Create a bucket and an application service account

Don't have Nextcloud authenticate as `root`. Create a bucket and a service account scoped only to that bucket.

In the MinIO Console:

1. **Buckets → Create Bucket** → name it `nextcloud-data`. Leave versioning off for now (we'll discuss in the troubleshooting section).
2. **Access Keys → Create access key**. Note the access key and secret key.
3. **Identity → Policies → Create policy**. Paste the policy below, name it `nextcloud-rw`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": [
        "arn:aws:s3:::nextcloud-data",
        "arn:aws:s3:::nextcloud-data/*"
      ]
    }
  ]
}
```

4. **Identity → Service Accounts** → attach the `nextcloud-rw` policy to the access key you just created.

**Why this matters:** the access key Nextcloud uses can read and write only `nextcloud-data`. If Nextcloud were ever compromised, the blast radius is bounded to that bucket — not the entire MinIO server. This is the cloud-security pattern of "least privilege" in microcosm. In AWS terms, you've just created an IAM user with a scoped IAM policy.

**Validation:** Use the `mc` MinIO client to verify the access key works only on its bucket:

```bash
# Install mc on your workstation if needed:
$ curl -O https://dl.min.io/client/mc/release/linux-amd64/mc
$ chmod +x mc && sudo mv mc /usr/local/bin/

# Configure an alias:
$ mc alias set lab http://minio.lab.internal:9000 <access-key> <secret-key>

$ mc ls lab/                       # should error or show only the bucket
$ mc ls lab/nextcloud-data         # should succeed (empty)
$ mc cp /etc/hostname lab/nextcloud-data/test.txt
$ mc ls lab/nextcloud-data         # shows test.txt
$ mc rm lab/nextcloud-data/test.txt
```

If `mc ls lab/` errors with AccessDenied but `mc ls lab/nextcloud-data` works, your IAM scoping is correct.

---

## Step 4 — Deploy Nextcloud

Nextcloud's Helm chart is more involved than MinIO's because there's more to configure: the database connection, the S3 backend, admin credentials, hostname, and persistence for things that aren't user file data (configs, app data).

```bash
$ helm repo add nextcloud https://nextcloud.github.io/helm/
$ helm repo update
```

Open `manifests/02-storage/nextcloud-values.yaml`. The interesting parts:

- `nextcloud.host: nextcloud.lab.internal` — must match what's in your `/etc/hosts`.
- `nextcloud.username: admin` and `nextcloud.password` (set via override below) — the initial admin user.
- `externalDatabase` — points at the Postgres service we deployed in step 2.
- `objectStore` — configures Nextcloud to use S3 (MinIO) as the *primary* object backend. This is the critical wiring.
- `persistence.enabled: true` for Nextcloud config files and app data — those still go on a normal PVC.

Generate the Nextcloud admin password and the S3 connection details:

```bash
$ NC_ADMIN_PASSWORD=$(openssl rand -base64 16)
$ MINIO_NC_ACCESS_KEY=<the access key you created in step 3a>
$ MINIO_NC_SECRET_KEY=<the secret key you created in step 3a>

$ cat <<EOF > manifests/02-storage/nextcloud-secrets.yaml
# Local override — DO NOT COMMIT
nextcloud:
  password: "${NC_ADMIN_PASSWORD}"
externalDatabase:
  password: "${NEXTCLOUD_DB_PASSWORD}"
objectStore:
  s3:
    key: "${MINIO_NC_ACCESS_KEY}"
    secret: "${MINIO_NC_SECRET_KEY}"
EOF

$ helm install nextcloud nextcloud/nextcloud \
    --namespace storage \
    -f manifests/02-storage/nextcloud-values.yaml \
    -f manifests/02-storage/nextcloud-secrets.yaml
```

Nextcloud's first boot is slow (1–3 minutes) because it runs the install script that creates database tables. Watch it:

```bash
$ kubectl -n storage get pods -l app.kubernetes.io/name=nextcloud -w
$ kubectl -n storage logs deployment/nextcloud -f
```

Look for `Nextcloud was successfully installed` in the logs.

---

## Step 5 — End-to-end verification

This is the test that makes the whole phase worth it.

1. Open `http://nextcloud.lab.internal` in your browser. Log in as `admin` with the password you generated.
2. Click **Files**, then upload any file (a screenshot, a text doc, anything).
3. Wait 5 seconds.
4. Open the MinIO Console at `http://minio.lab.internal:9001`. Browse the `nextcloud-data` bucket.
5. **You should see an object key that looks like `urn:oid:N` where N is a number.** That's the file you just uploaded, stored as an S3 object. Nextcloud uses internal numeric object IDs, not the original filename — the original filename → object ID mapping is in Postgres.

If you see an object in MinIO, you've proven the entire stack:

```
Browser → Ingress → Nextcloud pod → Postgres (metadata write)
                                  → MinIO (object write)
```

This is a microcosm of what every cloud SaaS does. You now have a defensible thing to point at and say "I built this."

---

## Validation checklist

- [ ] `kubectl get ns storage` shows Active with the `pod-security.kubernetes.io/enforce: baseline` label
- [ ] `kubectl -n storage get pods` shows `postgres-0`, `minio-...`, and `nextcloud-...` all `1/1 Running`
- [ ] `kubectl -n storage get pvc` shows three PVCs all `Bound`
- [ ] `psql` from a one-off pod connects successfully
- [ ] `mc ls lab/` is denied; `mc ls lab/nextcloud-data` works
- [ ] Nextcloud login works at the Ingress hostname
- [ ] An uploaded file appears as an object in the MinIO `nextcloud-data` bucket
- [ ] No secrets are committed — `git status` shows none of the `*-secrets.yaml` files staged

If any item is unchecked, fix it before moving on. Phase 04 assumes Nextcloud and MinIO are stable.

---

## Troubleshooting

**Postgres pod stuck `Pending` with "no nodes available".** Your local-path provisioner is having trouble on the chosen node. `kubectl describe pod postgres-0` will tell you why — usually a missing storage class or insufficient disk. Check with `kubectl get sc`; the default should be `local-path`.

**Nextcloud pod CrashLoopBackOff with "could not connect to server: Connection refused".** The Postgres service isn't resolvable yet. Verify `kubectl -n storage get svc postgres` returns a ClusterIP, and that `kubectl -n storage exec deployment/nextcloud -- nslookup postgres` resolves. Most likely Postgres just isn't ready yet — wait 60 seconds and the pod will restart on its own.

**Nextcloud login page loads but credentials fail.** The admin password you set in the values override doesn't match what Nextcloud actually used. Reset it:
```bash
$ kubectl -n storage exec deployment/nextcloud -- \
    su -p www-data -s /bin/sh -c "php occ user:resetpassword admin"
```

**Files upload to Nextcloud but no objects appear in MinIO.** Two common causes: (a) the S3 access key in your values override doesn't match the one in MinIO, or (b) the S3 endpoint URL Nextcloud is using points at the public Ingress instead of the internal cluster service. The cluster-internal endpoint is `http://minio.storage.svc.cluster.local:9000` — that's what the values file should specify, not the external Ingress hostname. Internal traffic should never go through Ingress.

**MinIO Console shows the bucket but `mc` says "AccessDenied" on operations.** Your service account access key isn't bound to the policy. Go back to MinIO Console → Identity → Service Accounts, edit the access key, attach the `nextcloud-rw` policy explicitly.

**Bucket versioning question.** You can enable versioning on the `nextcloud-data` bucket, but be aware Nextcloud doesn't manage S3 versions itself — versioning will just accumulate every write of every file forever, which fills disk fast. For lab purposes, leave it off.

---

## Key takeaways

- Deployed an S3-compatible object store with a stateful application using it as primary backend. Configured a per-application service account scoped to a single bucket — the same least-privilege pattern as an IAM user accessing S3 in AWS.
- Separated metadata (Postgres) from object data (MinIO). The architectural trade-offs: stable network identity for the database via StatefulSet, ReadWriteOnce volumes via local-path provisioner, and the resulting implications for HA.
- Activated Pod Security Standards at the baseline level on the storage namespace. `restricted` would block additional patterns (forced non-root, dropped capabilities, seccomp required); moving there is a production hardening step.
- Distinguished the MinIO root credential from IAM-style scoped access keys, and configured the application to use the scoped key.

## Next

Phase 04 — [Supply chain security](04-supply-chain.md). You'll scan the images you just deployed for CVEs, then layer in OPA Gatekeeper to enforce policies at admission time so future bad pods never get into the cluster.
