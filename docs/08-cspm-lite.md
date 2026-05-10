# Phase 08 — CSPM Lite (Prowler against AWS)

**Goal:** demonstrate end-to-end CSPM workflow against a real cloud. Create three deliberate misconfigurations in an AWS sandbox, scan with Prowler, triage the findings, remediate one, and re-scan to show clean.

**Time budget:** 2 hours. AWS account setup is the slowest part if you don't already have one.

**Why "lite":** the original phase 08 deployed a 7-finding Terraform stack against AWS. That's better pedagogy if you have time, but it's not needed to demonstrate competence. Three misconfigurations, click-deployed via the AWS console, are enough to walk through the full CSPM workflow in 2 hours.

**You will end up with:**
- An AWS sandbox account with three misconfigured resources
- A Prowler HTML report showing those misconfigurations as findings
- A triage note explaining what each finding means and how to fix it
- A remediation of one finding, with a re-scan showing it cleaned up
- A clear articulation of multi-cloud CSPM patterns

---

## Concepts

### CSPM, CNAPP, CWPP, CIEM, KSPM — vocabulary you will be tested on

If you only memorize five things from phase 08, memorize these:

| Acronym | Stands for | What it does |
|---|---|---|
| CSPM | Cloud Security Posture Management | Continuously evaluates cloud configurations against best practices and compliance frameworks. Output: misconfigurations. Examples: Wiz CSPM, Prisma Cloud CSPM, Defender CSPM, AWS Security Hub, Prowler, ScoutSuite. |
| CWPP | Cloud Workload Protection Platform | Runtime protection for VMs, containers, serverless. Output: runtime threats, malware, drift. Examples: Falco (your phase 05 work), Defender for Servers, Wiz Runtime Sensor. |
| CNAPP | Cloud-Native Application Protection Platform | Converged platform combining CSPM + CWPP + CIEM + IaC scanning + container/Kubernetes posture. Examples: Wiz, Orca, Prisma Cloud, Defender for Cloud. |
| CIEM | Cloud Infrastructure Entitlement Management | Identity-and-permissions-focused — finds over-privileged or unused identities. Examples: Wiz CIEM, Sonrai, AWS Access Analyzer. |
| KSPM | Kubernetes Security Posture Management | CSPM for Kubernetes specifically. Examples: kube-bench (your phase 07 work), Kubescape, Wiz/Orca/Prisma KSPM modules. |

These categories matter more than specific vendor names. "I've worked with CSPM tools — Defender for Cloud in Azure, Prowler for AWS" generalizes across the vendor space. Vendor-specific knowledge becomes secondary once the category mental model is in place.

### What Prowler does and how it differs from native tools

Prowler is open-source, runs from your workstation against an AWS/Azure/GCP account using read-only credentials, and produces a CIS / NIST / PCI-mapped report.

It overlaps with AWS Security Hub (which aggregates findings from GuardDuty, Config, Inspector, Macie, IAM Access Analyzer, and other AWS services), but with key differences:

| Aspect | Prowler | AWS Security Hub |
|---|---|---|
| Where it runs | Your workstation | Inside AWS |
| Cost | Free | ~$0.0010 per finding evaluated; can add up |
| Coverage | ~330+ checks across 60+ services | Foundational + CIS standards (and findings *from* other AWS services) |
| Output format | JSON, CSV, HTML, OCSF | Security Hub UI, also exportable |
| Real-time | No — scan when you run | Yes — continuous |

In a real environment you'd run both. In a lab Prowler is the right starting point.

### Reading IAM, the cloud-native deny-by-default

Cloud IAM is the de-facto perimeter in cloud. Most CSPM findings boil down to identity issues:

- **Over-privileged identity** — service account or role with `*:*`
- **Long-lived credentials** — access keys older than X days
- **No MFA** on human users
- **Public resources** — S3 bucket policy allowing `Principal: "*"`, or NSG/SG with `0.0.0.0/0`
- **Missing logging** — CloudTrail not enabled, S3 bucket logging off

Phase 08 deliberately includes a public S3 bucket, an IAM user with no MFA, and a wide-open security group — three of the most common CSPM finding categories.

---

## Prerequisites

- An AWS account. Free tier is fine.
- AWS CLI v2 installed and configured with credentials for that account.
- Prowler installed (`pipx install prowler`).
- The account's root credentials secured with MFA. Don't use root for any of this.
- Budget alarm set at $5 or $10 — the lab spend should be near zero, but always set a guardrail.

---

## Step 1 — Set up a sandbox IAM user

Don't run Prowler as root. Create a least-privilege scanner identity.

In the AWS console:

1. **IAM → Users → Create user** named `prowler-scanner`.
2. Attach two AWS-managed policies:
   - `arn:aws:iam::aws:policy/SecurityAudit`
   - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`
3. Create an access key for the user. Note the key and secret.
4. Configure your CLI:

```bash
$ aws configure --profile sec-lab-prowler
# paste keys, set region us-east-1
$ aws sts get-caller-identity --profile sec-lab-prowler
# should return the new user's ARN
```

---

## Step 2 — Create the three intentional misconfigurations

We're using the console, not Terraform, to keep this fast.

### Misconfig 1 — Public S3 bucket

In the AWS console (using your **regular** admin account, not the Prowler scanner):

1. **S3 → Create bucket** → name `sec-lab-public-<some-random-suffix>` → uncheck "Block all public access" → confirm the warning.
2. After creation, **Permissions → Bucket policy** → paste:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::sec-lab-public-<your-suffix>/*"
  }]
}
```

Upload any small file. Note the public URL.

### Misconfig 2 — IAM user without MFA

1. **IAM → Users → Create user** named `sec-lab-orphan-user`.
2. Attach `AmazonS3ReadOnlyAccess` (any non-empty permission so the user shows up in scans).
3. Skip the MFA setup.

### Misconfig 3 — Security group open to the world on SSH

1. **VPC → Security Groups → Create** named `sec-lab-open-ssh`.
2. Inbound rule: TCP 22 from `0.0.0.0/0`.
3. (You don't need to attach this to an EC2 instance — Prowler will flag the SG by itself.)

---

## Step 3 — Run Prowler

```bash
$ mkdir -p scans/prowler-aws
$ prowler aws \
    --profile sec-lab-prowler \
    --output-formats csv html json-asff \
    --output-directory scans/prowler-aws \
    --severity high critical
```

Prowler will print a running tally. When it finishes, you'll have several files in `scans/prowler-aws/`:

- An HTML report — open in your browser
- A CSV — easy to filter and triage
- An ASFF JSON — the AWS Security Hub-compatible format

Open the HTML report. Use the filters to find your three intentional findings:

- "Bucket has public access" or "S3 buckets accessible to the world"
- "IAM users have MFA disabled"
- "Security groups allow ingress from 0.0.0.0/0 to port 22"

---

## Step 4 — Triage

For each of your three intentional findings, write a one-paragraph triage in `scans/prowler-triage.md`:

```markdown
# Prowler Triage — sec-lab AWS account

## Finding: S3 bucket sec-lab-public-xxxx is public
- **Severity:** Critical
- **CIS control:** 1.20 (Ensure S3 buckets are not publicly accessible)
- **Risk:** Anyone on the Internet can list and download objects. If the bucket holds PII or any internal data, that's an immediate breach.
- **Remediation:** Enable Block Public Access at the bucket level; remove the public Allow statement from the bucket policy.
- **Ticket title:** [Critical] Public S3 bucket: sec-lab-public-xxxx

## Finding: IAM user sec-lab-orphan-user has no MFA
- **Severity:** High
- **CIS control:** 1.10 (Ensure MFA is enabled for all IAM users with a console password)
- **Risk:** Account takeover via credential reuse / phishing. MFA is the primary mitigation.
- **Remediation:** Enable MFA on the user, or remove the user if not in use.
- **Ticket title:** [High] IAM user without MFA: sec-lab-orphan-user

## Finding: Security group sec-lab-open-ssh allows 0.0.0.0/0 on port 22
- **Severity:** High
- **CIS control:** 5.2 (Ensure no SGs allow ingress from 0.0.0.0/0 to port 22)
- **Risk:** Any EC2 instance using this SG would be reachable for SSH brute force from the entire internet.
- **Remediation:** Restrict ingress to specific known CIDR (your office/VPN egress); or replace with SSM Session Manager (no SSH at all).
- **Ticket title:** [High] SSH open to world: sg-xxxxxxxx
```

These three writeups are the artifact for the "walk me through how you triage CSPM findings" scenario.

---

## Step 5 — Remediate one finding and re-scan

Pick the most demonstrable: **the public S3 bucket**. Block public access at the bucket level:

```bash
$ aws s3api put-public-access-block \
    --bucket sec-lab-public-<your-suffix> \
    --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --profile sec-lab-prowler

# Try the public URL again — should now be 403
$ curl -I https://sec-lab-public-<your-suffix>.s3.amazonaws.com/<your-file>
# HTTP/1.1 403 Forbidden
```

Re-run Prowler:

```bash
$ prowler aws \
    --profile sec-lab-prowler \
    --check s3_bucket_public_access \
    --output-formats csv html \
    --output-directory scans/prowler-aws-after \
    --severity high critical
```

The S3 finding should now show as PASS for that bucket. The IAM and SG findings still FAIL (you didn't remediate those — leave them as before/after evidence).

---

## Step 6 — Compare with AWS Security Hub (optional, 30 min)

Optional: enable Security Hub in your region with the AWS Foundational Security Best Practices and CIS standards. Wait 20 minutes for findings to populate, then look at the same three resources in the Security Hub console. You'll see overlap with Prowler — and where they diverge is the interesting part of the comparison.

---

## Step 7 — Cleanup (don't skip this)

```bash
# Delete the public bucket
$ aws s3 rb s3://sec-lab-public-<your-suffix> --force --profile <admin>

# Delete the IAM user
$ aws iam delete-user --user-name sec-lab-orphan-user --profile <admin>

# Delete the security group
$ aws ec2 delete-security-group --group-name sec-lab-open-ssh --profile <admin>
```

You can keep the `prowler-scanner` IAM user; it has read-only permissions and useful for future runs.

---

## Validation checklist

- [ ] Three intentional misconfigurations were created and visible in AWS console
- [ ] Prowler scanned and produced HTML / CSV / JSON output in `scans/prowler-aws/`
- [ ] All three intentional misconfigs appear in the Prowler report as findings
- [ ] You have `scans/prowler-triage.md` with one paragraph per finding
- [ ] One finding (S3 public) is remediated; re-scan shows it as PASS
- [ ] Cleanup is done (no lingering misconfigured resources or you'll be charged for the EC2 / SG / IAM in worst case)

---

## Multi-cloud bonus (skip if time-pressed)

You're already comfortable in Azure. Run the same exercise in 30 minutes:

```bash
$ az login
$ prowler azure --az-cli-auth --severity high critical \
    --output-directory scans/prowler-azure
```

Talking point: "I've used Defender for Cloud in production and validated my findings cross-tool with Prowler. Prowler's value is portability — same workflow across AWS, Azure, GCP."

For GCP, same pattern with a service account:

```bash
$ prowler gcp --credentials-file ~/sec-lab-key.json \
    --project-id sec-lab \
    --severity high critical \
    --output-directory scans/prowler-gcp
```

---

## Key takeaways

- Ran Prowler against an AWS sandbox: three intentional misconfigurations (public S3 bucket, IAM user without MFA, SSH-open security group), one remediated with before/after scan evidence.
- Prowler is open-source CSPM running from outside the cloud, which is useful for cross-cloud workflows. AWS Security Hub aggregates findings *from* AWS services like GuardDuty and Macie — different tool, complementary not redundant.
- Vocabulary: CSPM finds misconfigurations, CWPP protects workloads at runtime, CIEM focuses on identity entitlements, KSPM is CSPM for Kubernetes, CNAPP is the converged platform that bundles them. Wiz, Orca, Prisma — all CNAPPs.
- Triage isn't just severity sorting. Exposure (internet-facing?), reachability (does the misconfig actually expose data?), and ownership (whose team owns it?) matter as much as severity. "Public S3" is more urgent than "CloudTrail not enabled in unused region."

## Next

Phase 09 — [ATT&CK coverage](09-attack-coverage.md). You'll build a coverage matrix mapping the detections you have (Falco rules, NetworkPolicy, Gatekeeper, CSPM findings) against MITRE ATT&CK Cloud and Container techniques.
