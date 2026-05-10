# Phase 09 — MITRE ATT&CK Coverage Matrix

**Goal:** map the detections, preventions, and visibility you've built across phases 02–08 against the MITRE ATT&CK framework. Produce a coverage matrix that shows what techniques you'd catch, where the gaps are, and what you'd add next.

**Time budget:** 1.5 hours.

**Why this exists:** the JD specifically calls out "mapping system defenses and monitoring capabilities against threat frameworks like MITRE ATT&CK and OWASP." A filled-in coverage matrix is one of the highest-signal artifacts you can bring to a panel because it shows you don't just install tools — you reason about what they catch.

**You will end up with:**
- A coverage matrix in `docs/09-attack-coverage.md` (this file becomes the deliverable)
- A markdown table you can paste into your repo README, your portfolio, or a slide

---

## Concepts

### MITRE ATT&CK in 60 seconds

ATT&CK is a publicly maintained matrix of adversary tactics (the "why" — initial access, persistence, exfiltration) and techniques (the "how" — phishing, valid accounts, data from cloud storage). Each technique has an ID like `T1078.004` and documents the behavior, detection guidance, and known threat groups using it.

Several "matrices" exist for different domains. Cloud-relevant ones:

- **ATT&CK Enterprise** — the main matrix
- **ATT&CK for Cloud** — IaaS, SaaS, Identity Provider sub-matrices
- **ATT&CK for Containers** — runtime-only techniques like T1610 (Deploy Container)

### Why coverage matters more than count

It's tempting to claim coverage by tool count: "I run Falco, GuardDuty, CloudTrail — I have detection." Panels probe deeper. A coverage matrix forces you to answer:

- Which specific techniques can each tool detect?
- What's the signal? (rule name, log field, alert type)
- What's the *quality* of the detection? Reliable, partial, or theoretical?
- Where are the gaps?

That's the conversation panels actually want to have.

### Coverage scoring model

Use a simple 4-level scale:

- **Detect** — the technique would generate an alert with current configuration
- **Partial** — the technique would generate telemetry but not necessarily alert
- **Visibility** — the data would be captured but no detection logic exists
- **Gap** — no telemetry, no detection

This shows nuance without overcomplicating. Avoid percentage-based "coverage" claims; they're meaningless without context.

---

## How to use this matrix

This file is meant to live in your repo as a reference and an artifact. Update it as your lab evolves. For the interview, print or have it open during the panel; reference specific cells when answering technique-related questions.

---

## Coverage matrix — current state

| TTP ID | Technique | Tactic | Status | Signal / Source | Notes |
|---|---|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access / Persistence | Detect | CloudTrail + Prowler check on inactive privileged users | A user logging in from an unknown IP would also generate GuardDuty UnauthorizedAccess. Add MFA enforcement via SCPs in production. |
| T1098.001 | Account Manipulation: Add Cloud Credentials | Persistence | Detect | CloudTrail event `CreateAccessKey` | Custom CloudWatch alarm could fire on CreateAccessKey by non-pipeline identity. |
| T1098.003 | Add Privileges to Cloud Account | Privilege Escalation | Partial | CloudTrail `AttachUserPolicy` / `AttachRolePolicy` events captured | No alerting rule built yet — gap to fix. |
| T1190 | Exploit Public-Facing Application | Initial Access | Visibility | Suricata in Security Onion, Nextcloud access logs | No automated rule for app-layer exploit chains. |
| T1525 | Implant Internal Image | Persistence | Detect | OPA Gatekeeper `K8sAllowedRepos` constraint | Blocks images outside trusted registries at admission. |
| T1530 | Data from Cloud Storage | Collection | Partial | CloudTrail S3 data events (if enabled), MinIO audit logs | S3 data events not enabled in lab AWS — would alert on mass GetObject. Costs extra in production. |
| T1552.001 | Credentials in Files | Credential Access | Detect | Custom Falco rule (`Cloud credential file read`) | Phase 05 custom rule. Maps to specific ATT&CK ID. |
| T1552.005 | Cloud Instance Metadata API | Credential Access | Gap | None | Mitigation: IMDSv2 enforced via SCP. Detection: CloudTrail + flow logs to spot unusual IMDS calls. |
| T1610 | Deploy Container | Execution | Detect | Falco "Container drift detected" + Kubernetes audit log | Auditing kubectl create / apply. |
| T1611 | Escape to Host | Privilege Escalation | Detect | Falco "Privileged container started" + Gatekeeper deny-privileged constraint | Two layers: Gatekeeper prevents at admission, Falco catches at runtime if a privileged container somehow runs. |
| T1612 | Build Image on Host | Defense Evasion | Visibility | Falco docker.sock detection rule available but not enabled | Easy to enable; will do. |
| T1613 | Container and Resource Discovery | Discovery | Partial | Kubernetes audit log of `list/get` on cluster resources | No alerting on API discovery currently. |
| T1496 | Resource Hijacking (cryptomining) | Impact | Partial | Falco rules for shell + outbound network; GuardDuty Crypto findings | GuardDuty would detect mining-pool destinations. Falco's default rules catch some patterns. |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Defense Evasion | Visibility | CloudTrail captures DeleteVirtualMFADevice / DeactivateMFADevice | No alerting rule. |
| T1485 | Data Destruction | Impact | Partial | S3 versioning + bucket policy audit | If versioning + MFA-Delete were on, T1485 against S3 would be recoverable. Lab has versioning off. |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | Detect | CloudTrail + Falco rule for tampering with /etc/falco | If an attacker tries to disable Falco itself, the syscall hits before the daemon dies. |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | Detect | Falco "Terminal shell in container" rule | Default Falco rule. Phase 05 evidence file. |
| T1567 | Exfiltration Over Web Service | Exfiltration | Partial | Custom Falco rule (`Unexpected egress from MinIO container`) | Phase 05 custom rule, monitors only the MinIO container. Should expand to other workloads. |

---

## Gaps and roadmap

The matrix above shows where you're light. Three gaps worth flagging in the panel:

1. **T1552.005 (Instance Metadata API abuse)** — In a real cloud environment with EC2, this is critical. Mitigation: enforce IMDSv2 via SCP. Detection: VPC flow logs into Athena queries looking for unusual 169.254.169.254 access patterns. **Action**: add to roadmap.

2. **T1556.006 (MFA modification)** — CloudTrail already captures the events but no alert rule. Easy fix: CloudWatch alarm or Security Hub custom insight on `DeactivateMFADevice` / `DeleteVirtualMFADevice`. **Action**: add to roadmap.

3. **T1612 (Build image on host)** — Falco has a default rule for this but it's not enabled in the lab values. **Action**: enable in Phase 05's `falco-values.yaml`.

---

## How to talk about this in an interview

When asked "how do you map detection to threats?" — pull up this matrix and walk through it. Specific cells matter more than aggregate scores:

- "T1098.001 — adding cloud credentials — I detect via CloudTrail's `CreateAccessKey` event. In production I'd add a CloudWatch alarm scoped to non-pipeline identities."
- "T1611 — container escape — I cover at two layers: OPA Gatekeeper blocks privileged containers at admission, and Falco's privileged-container rule fires at runtime in case anything slipped through."
- "T1552.005 — IMDS abuse — that's a gap in my lab. I know the detection pattern: VPC flow logs filtered to 169.254.169.254 with anomaly detection on volume. Mitigation is enforcing IMDSv2 via SCP."

Showing where you have gaps is *more* convincing than claiming full coverage. Real coverage is never 100%; engineers who claim it is haven't thought hard enough.

---

## OWASP Cloud-Native Top 10 — quick map

The JD also references OWASP. Be ready to one-line each:

- **CNAS-1** Insecure cloud, container, or orchestration configuration → covered by Phase 04 Gatekeeper, Phase 07 kube-bench, Phase 08 Prowler
- **CNAS-2** Injection flaws → application-level, not directly addressed in this lab
- **CNAS-3** Improper authentication and authorization → Phase 02 IAM-scoped MinIO key, Phase 08 IAM findings
- **CNAS-4** CI/CD pipeline & supply chain flaws → Phase 04 Trivy, partially. Cosign image signing is the next layer.
- **CNAS-5** Insecure secrets storage → Kubernetes Secrets used (base64 only, not encrypted by default). External Secrets / Vault would be the next step.
- **CNAS-6** Over-permissive network policies → Phase 06 default-deny + explicit allows
- **CNAS-7** Using vulnerable components → Phase 04 Trivy CVE scanning
- **CNAS-8** Improper assets management → covered conceptually in your homelab inventory but not a deliverable here
- **CNAS-9** Inadequate observability → Phase 05 Falco → Security Onion
- **CNAS-10** Insecure key management → MinIO IAM model in Phase 02; KMS-backed encryption is the next layer

---

## Validation checklist

- [ ] Matrix has at least 15 techniques
- [ ] Each row identifies signal/source
- [ ] At least 3 gaps clearly identified with actions
- [ ] OWASP Cloud-Native Top 10 mapped to phase work
- [ ] You can verbally walk through any cell in the matrix

## Next

Phase 10 — [IR runbook](10-ir-runbook.md). You'll write an incident response playbook for one scenario tied to a Falco detection — closing the loop from detection back to action.
