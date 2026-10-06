# DevSecOps Security Policy Registry
**Project:** CS587-CS588 Capstone — Secure DevSecOps Pipeline  
**Owner:** Sakshi (Policy, Risk & Compliance Lead)  
**Framework:** NIST SP 800-53 (Rev 5)  
**Pipeline Platform:** GitLab CI/CD  
**Pipeline Stages:** `test` → `triage`  
**Active Scanners:** Semgrep (SAST), GitLab Secret Detection  
**AI Triage Layer:** AWS Bedrock (`ai` branch only — advisory only)  
**Version:** 2.0  
**Last Updated:** 2026-04-22  
**Status:** Active

---

## Table of Contents

1. [How This Document Works](#1-how-this-document-works)
2. [Severity Thresholds & Risk Scoring](#2-severity-thresholds--risk-scoring)
3. [Pipeline Enforcement Map](#3-pipeline-enforcement-map)
4. [Area 1 — Code Security (SAST)](#4-area-1--code-security-sast)
5. [Area 2 — Dependency Security (SCA)](#5-area-2--dependency-security-sca)
6. [Area 3 — Secrets Detection](#6-area-3--secrets-detection)
7. [Area 4 — Infrastructure as Code (IaC)](#7-area-4--infrastructure-as-code-iac)
8. [AI Triage Governance Policy](#8-ai-triage-governance-policy)
9. [NIST SP 800-53 Control Mapping](#9-nist-sp-800-53-control-mapping)
10. [Incident Response Procedures](#10-incident-response-procedures)
11. [Exception Process & Log](#11-exception-process--log)
12. [Changelog](#12-changelog)

---

## 1. How This Document Works

This registry defines every security policy enforced in the CI/CD pipeline. It is the authoritative source of truth for what is allowed, what is blocked, and why.

Each policy defines:
- The security rule and what it protects against
- Which pipeline stage enforces it
- Which scanner detects violations
- A risk score and gate action
- The NIST SP 800-53 control it satisfies

### Gate Actions

| Action | Symbol | Meaning |
|---|---|---|
| BLOCK | 🔴 | Pipeline job fails. Merge request cannot be merged. Deployment is halted. |
| WARN | 🟡 | Pipeline passes with a warning. Finding is logged. Must be reviewed within 48 hours. |
| PASS | 🟢 | No violation detected. Pipeline continues. |

### Pipeline Stage Ownership

| Stage | Purpose | Owner |
|---|---|---|
| `test` | Runs all security scanners (SAST, Secret Detection) | Yilu |
| `triage` | AI summarizes and triages findings (advisory only) | Sakshi (governance) |

---

## 2. Severity Thresholds & Risk Scoring

### Severity Definitions

| Severity | CVSS Range | Definition | Gate Action |
|---|---|---|---|
| **Critical** | 9.0 – 10.0 | Directly exploitable, immediate threat, exposed secrets, or zero-click attack surface | 🔴 BLOCK |
| **High** | 7.0 – 8.9 | Significant vulnerability, exploitable with low effort or common tools | 🔴 BLOCK |
| **Medium** | 4.0 – 6.9 | Limited exploitability, requires specific conditions or chained attack | 🟡 WARN |
| **Low** | 0.1 – 3.9 | Minor issue, best-practice deviation, no direct exploitability | 🟡 WARN |
| **Info** | N/A | Informational only, no security risk | 🟢 PASS |

### Risk Scoring Matrix

Each finding receives a **Risk Score (1–25)** calculated as:

```
Risk Score = Likelihood (1–5) × Impact (1–5)
```

| Score Range | Risk Level | Action Required |
|---|---|---|
| 20 – 25 | 🔴 Critical Risk | Immediate block. Must be remediated before any merge. |
| 15 – 19 | 🔴 High Risk | Block. Remediation required within 24 hours. |
| 10 – 14 | 🟡 Medium Risk | Warn. Reviewed and documented within 48 hours. |
| 5 – 9 | 🟡 Low Risk | Warn. Logged and tracked in next sprint. |
| 1 – 4 | 🟢 Minimal Risk | Pass. Noted for future hardening. |

### Likelihood Scale

| Score | Likelihood | Description |
|---|---|---|
| 5 | Almost Certain | Widely known exploit, active CVE, or trivially reproducible |
| 4 | Likely | Exploit exists, requires minimal skill |
| 3 | Possible | Exploit exists but requires specific conditions |
| 2 | Unlikely | Theoretical vulnerability, no known exploit |
| 1 | Rare | Extremely unlikely under normal conditions |

### Impact Scale

| Score | Impact | Description |
|---|---|---|
| 5 | Catastrophic | Full system compromise, data breach, credential exposure |
| 4 | Major | Significant data loss, unauthorized access, service disruption |
| 3 | Moderate | Partial system impact, limited data exposure |
| 2 | Minor | Minimal impact, no data loss |
| 1 | Negligible | No meaningful security impact |

---

## 3. Pipeline Enforcement Map

This shows exactly where each policy area is enforced in the current `.gitlab-ci.yml`:

```
Push / Merge Request
        │
        ▼
┌─────────────────────────────────────────────┐
│              STAGE: test                    │
│                                             │
│  semgrep-sast job                           │
│  └── Enforces: CODE policies (CODE-01–08)   │
│  └── Output: gl-sast-report.json            │
│                                             │
│  secret_detection job                       │
│  └── Enforces: Secrets policies (SEC-01–06) │
│  └── Output: gl-secret-detection-report.json│
│                                             │
│  [DEP and IAC scanners: planned - not yet   │
│   active. See Milestone 2 scope.]           │
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│              STAGE: triage                  │
│  (runs only on `ai` branch)                 │
│                                             │
│  ai_triage job (AWS Bedrock)                │
│  └── Reads: gl-sast-report.json             │
│  └── Reads: gl-secret-detection-report.json │
│  └── Outputs: out/decision.json             │
│  └── Outputs: out/summary.md                │
│  └── ADVISORY ONLY — cannot block pipeline  │
└─────────────────────────────────────────────┘
        │
        ▼
   Merge Allowed / Blocked
```

### Current Scanner Coverage

| Area | Scanner | Status | GitLab Job Name |
|---|---|---|---|
| Code (SAST) | Semgrep | ✅ Active | `semgrep-sast` |
| Secrets | GitLab Secret Detection | ✅ Active | `secret_detection` |
| Dependencies (SCA) | Trivy (planned) | 🔄 Pending Milestone 2 | TBD |
| IaC | Checkov (planned) | 🔄 Pending Milestone 2 | TBD |

---

## 4. Area 1 — Code Security (SAST)

> **Scanner:** Semgrep via `semgrep-sast` job (GitLab SAST template)  
> **Stage:** `test`  
> **Output file:** `gl-sast-report.json`

| Policy ID | Policy Name | Description | Likelihood | Impact | Risk Score | Severity | Gate Action | NIST Control |
|---|---|---|---|---|---|---|---|---|
| CODE-01 | No SQL Injection | Code must not pass unsanitized user input into SQL queries | 5 | 5 | 25 | Critical | 🔴 BLOCK | SI-10 |
| CODE-02 | No Command Injection | Code must not pass unsanitized input to shell or OS commands | 5 | 5 | 25 | Critical | 🔴 BLOCK | SI-10 |
| CODE-03 | No Cross-Site Scripting (XSS) | Code must sanitize all output rendered in a browser context | 4 | 4 | 16 | High | 🔴 BLOCK | SI-10 |
| CODE-04 | No Insecure Deserialization | Untrusted data must not be deserialized without validation | 3 | 5 | 15 | High | 🔴 BLOCK | SI-10 |
| CODE-05 | No Hardcoded Credentials in Code | Source code must not contain passwords, tokens, or keys as string literals | 5 | 5 | 25 | Critical | 🔴 BLOCK | IA-5 |
| CODE-06 | No Deprecated Cryptography | Code must not use MD5, SHA-1, or DES for security operations | 4 | 4 | 16 | High | 🔴 BLOCK | SC-13 |
| CODE-07 | No Path Traversal | File path inputs must be validated and restricted to allowed directories | 4 | 4 | 16 | High | 🔴 BLOCK | SI-10 |
| CODE-08 | No Unsafe Redirects | All redirect URLs must be validated against an allowlist | 3 | 3 | 9 | Medium | 🟡 WARN | SI-10 |
| CODE-09 | Error Handling Must Not Expose Internals | Errors must not return stack traces, file paths, or DB schema to users | 3 | 3 | 9 | Medium | 🟡 WARN | SI-11 |
| CODE-10 | No Debug Code in Production Builds | Debug flags and sensitive print statements must be removed before merge | 2 | 2 | 4 | Low | 🟡 WARN | CM-6 |

---

## 5. Area 2 — Dependency Security (SCA)

> **Scanner:** Trivy (planned — pending Milestone 2 integration)  
> **Stage:** `test` (when integrated)  
> **Output file:** `trivy-report.json` (planned)  
> ⚠️ *Requires application code with a dependency file (requirements.txt, package.json, etc.) to be added to the repo.*

| Policy ID | Policy Name | Description | Likelihood | Impact | Risk Score | Severity | Gate Action | NIST Control |
|---|---|---|---|---|---|---|---|---|
| DEP-01 | No Critical CVEs in Dependencies | No dependency may have a CVE with CVSS ≥ 9.0 | 5 | 5 | 25 | Critical | 🔴 BLOCK | RA-5 |
| DEP-02 | No High CVEs in Dependencies | No dependency may have a CVE with CVSS 7.0–8.9 | 4 | 4 | 16 | High | 🔴 BLOCK | RA-5 |
| DEP-03 | No Unreviewed Medium CVEs | Dependencies with CVSS 4.0–6.9 must be logged and reviewed within 48 hours | 3 | 3 | 9 | Medium | 🟡 WARN | RA-5 |
| DEP-04 | No Unpinned Dependency Versions | All dependencies must specify exact version numbers, not ranges or wildcards | 3 | 3 | 9 | Medium | 🟡 WARN | CM-6 |
| DEP-05 | No Abandoned Packages | Dependencies with no maintenance activity in 2+ years must be flagged | 2 | 3 | 6 | Low | 🟡 WARN | SA-22 |
| DEP-06 | No Unapproved Licenses | Dependencies must use OSI-approved open source licenses | 2 | 2 | 4 | Low | 🟡 WARN | SA-4 |

---

## 6. Area 3 — Secrets Detection

> **Scanner:** GitLab Secret Detection template via `secret_detection` job  
> **Stage:** `test`  
> **Output file:** `gl-secret-detection-report.json`

> ⚠️ **Zero Tolerance Policy:** Any secret detected anywhere in the repository — regardless of whether it appears active or was deleted in a prior commit — **immediately blocks the pipeline**. There are no warnings for secrets. This applies to all branches.

| Policy ID | Policy Name | Description | Likelihood | Impact | Risk Score | Severity | Gate Action | NIST Control |
|---|---|---|---|---|---|---|---|---|
| SEC-01 | No AWS Access Keys | No AWS access key IDs or secret access keys in any file or commit history | 5 | 5 | 25 | Critical | 🔴 BLOCK | IA-5 |
| SEC-02 | No API Tokens or Bearer Tokens | No API tokens, bearer tokens, or OAuth secrets in any file | 5 | 5 | 25 | Critical | 🔴 BLOCK | IA-5 |
| SEC-03 | No Database Credentials | No database usernames, passwords, or connection strings in code or config | 5 | 5 | 25 | Critical | 🔴 BLOCK | IA-5 |
| SEC-04 | No Private Keys or Certificates | No private SSH keys, TLS certificates, or PEM files committed to the repo | 5 | 5 | 25 | Critical | 🔴 BLOCK | SC-12 |
| SEC-05 | No .env Files Committed | .env files containing environment variables must never be committed | 5 | 5 | 25 | Critical | 🔴 BLOCK | IA-5 |
| SEC-06 | No High-Entropy Credential Strings | Strings with entropy patterns matching credential format must be flagged | 4 | 5 | 20 | Critical | 🔴 BLOCK | IA-5 |
| SEC-07 | Secrets Must Use GitLab CI Variables | All secrets used in the pipeline must be stored as GitLab CI/CD masked variables, not hardcoded in `.gitlab-ci.yml` | 5 | 5 | 25 | Critical | 🔴 BLOCK | IA-5 |

---

## 7. Area 4 — Infrastructure as Code (IaC)

> **Scanner:** Checkov (planned — pending Milestone 2 integration)  
> **Stage:** `test` (when integrated)  
> **Output file:** `checkov-report.json` (planned)

| Policy ID | Policy Name | Description | Likelihood | Impact | Risk Score | Severity | Gate Action | NIST Control |
|---|---|---|---|---|---|---|---|---|
| IAC-01 | No Publicly Accessible Storage Buckets | S3 buckets must not have public read/write ACLs | 4 | 5 | 20 | Critical | 🔴 BLOCK | AC-3 |
| IAC-02 | No Unrestricted Inbound Rules | Security groups must not allow 0.0.0.0/0 on ports 22, 3389, or 5432 | 5 | 5 | 25 | Critical | 🔴 BLOCK | SC-7 |
| IAC-03 | Encryption at Rest Required | All storage resources must have encryption enabled | 4 | 4 | 16 | High | 🔴 BLOCK | SC-28 |
| IAC-04 | Encryption in Transit Required | All network resources must enforce TLS 1.2 or higher | 4 | 4 | 16 | High | 🔴 BLOCK | SC-8 |
| IAC-05 | No Root Account Usage in IAM | IAM configs must not assign permissions to the root account | 4 | 5 | 20 | Critical | 🔴 BLOCK | AC-6 |
| IAC-06 | Containers Must Not Run as Root | Dockerfiles and pod specs must define a non-root user | 4 | 4 | 16 | High | 🔴 BLOCK | AC-6 |
| IAC-07 | No Latest Tag on Container Images | Images must pin to a specific version tag, not `latest` | 3 | 3 | 9 | Medium | 🟡 WARN | CM-6 |
| IAC-08 | Logging Must Be Enabled on All Resources | Cloud resources must have logging and monitoring enabled | 3 | 4 | 12 | Medium | 🟡 WARN | AU-2 |
| IAC-09 | MFA Must Be Enforced on IAM Users | All IAM user accounts must require multi-factor authentication | 4 | 5 | 20 | Critical | 🔴 BLOCK | IA-2 |
| IAC-10 | No Hardcoded IPs in Infrastructure Config | Infrastructure configs must not hardcode IP addresses | 2 | 3 | 6 | Low | 🟡 WARN | CM-6 |

---

## 8. AI Triage Governance Policy

> This section governs the behavior of the `ai_triage` job in the pipeline, which uses AWS Bedrock to summarize and triage security findings.

### 8.1 Core Principles

| Principle | Rule |
|---|---|
| **Advisory Only** | AI output is never the final enforcement decision. The pipeline gate is always determined by scanner results, not AI output. |
| **Evidence-Grounded** | AI must only reference findings that exist in `gl-sast-report.json` or `gl-secret-detection-report.json`. AI may not introduce new vulnerability claims. |
| **No Severity Override** | AI may not change the severity level assigned by the scanner. If Semgrep says Critical, AI cannot downgrade it to Medium. |
| **Data Redaction** | Secrets, tokens, file paths containing credentials, and usernames must be redacted before being sent to the Bedrock model. |
| **Scope Limited** | AI triage runs only on the `ai` branch. It does not run on `main` or feature branches by default. |
| **Fallback Required** | If AI output is invalid, malformed, or times out, the system must fall back to a rule-based summary. The pipeline must never fail silently. |

### 8.2 Required Output Schema

The `ai_triage` job must produce `out/decision.json` matching this exact schema. Any output that does not validate against this schema must be rejected and trigger the fallback:

```json
{
  "schema_version": "1.0",
  "generated_by": "ai_triage",
  "advisory_only": true,
  "findings_summary": {
    "total_findings": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0
  },
  "triage_results": [
    {
      "finding_id": "string — must match scanner finding ID",
      "source_scanner": "semgrep-sast | secret_detection",
      "original_severity": "Critical | High | Medium | Low | Info",
      "ai_suggested_priority": "Immediate | High | Normal | Low",
      "reasoning": "string — must cite evidence from scanner output",
      "recommended_action": "string — specific remediation step",
      "evidence_ref": "string — file and line number from scanner output"
    }
  ],
  "overall_risk_assessment": "string — 2–3 sentence summary, no new claims",
  "ai_confidence": "High | Medium | Low",
  "fallback_used": false
}
```

### 8.3 Fallback Behavior

If AI output fails schema validation or the Bedrock call fails, the system must:

1. Log the failure reason to the pipeline job log
2. Set `fallback_used: true` in `decision.json`
3. Generate a rule-based summary from raw scanner JSON with the following fields populated from scanner data only: `findings_summary`, `triage_results` (severity mapped directly from scanner), `overall_risk_assessment` (auto-generated text: "Scanner detected N critical, N high findings. Manual review required.")
4. Never block the pipeline due to AI failure alone — the `test` stage gate is always the authoritative enforcement point

### 8.4 What AI Is Not Allowed To Do

- ❌ Override or change a scanner's severity rating
- ❌ Claim a vulnerability exists that is not in the scanner report
- ❌ Recommend approving a merge request
- ❌ Access, log, or transmit raw secret values
- ❌ Produce output that bypasses the JSON schema validation step

---

## 9. NIST SP 800-53 Control Mapping

| NIST Control | Control Name | Policy IDs Mapped | Pipeline Enforced By |
|---|---|---|---|
| AC-3 | Access Enforcement | IAC-01 | Checkov (planned) |
| AC-6 | Least Privilege | IAC-05, IAC-06 | Checkov (planned) |
| AU-2 | Event Logging | IAC-08 | Checkov (planned) |
| CM-6 | Configuration Settings | CODE-10, DEP-04, IAC-07, IAC-10 | Semgrep, Trivy, Checkov |
| IA-2 | Identification & Authentication | IAC-09 | Checkov (planned) |
| IA-5 | Authenticator Management | CODE-05, SEC-01–07 | Semgrep, Secret Detection |
| RA-5 | Vulnerability Scanning | DEP-01, DEP-02, DEP-03 | Trivy (planned) |
| SA-4 | Acquisition Process | DEP-06 | Trivy (planned) |
| SA-22 | Unsupported System Components | DEP-05 | Trivy (planned) |
| SC-7 | Boundary Protection | IAC-02 | Checkov (planned) |
| SC-8 | Transmission Confidentiality | IAC-04 | Checkov (planned) |
| SC-12 | Cryptographic Key Management | SEC-04 | Secret Detection |
| SC-13 | Cryptographic Protection | CODE-06 | Semgrep |
| SC-28 | Protection at Rest | IAC-03 | Checkov (planned) |
| SI-10 | Information Input Validation | CODE-01–04, CODE-07–08 | Semgrep |
| SI-11 | Error Handling | CODE-09 | Semgrep |

---

## 10. Incident Response Procedures

> These procedures define how the team responds when a policy violation is detected by the pipeline. Response time targets are based on severity.

### 10.1 Response Time Targets

| Severity | Detection | Acknowledgement | Remediation | Re-scan |
|---|---|---|---|---|
| Critical | Immediate (pipeline blocks) | Within 1 hour | Within 24 hours | Within 24 hours |
| High | Immediate (pipeline blocks) | Within 4 hours | Within 48 hours | Within 48 hours |
| Medium | Pipeline warns | Within 24 hours | Within 1 week | Within 1 week |
| Low | Pipeline warns | Within 1 week | Next sprint | Next sprint |

### 10.2 Procedure by Finding Type

#### 🔴 Secret Detected (SEC-01 through SEC-07)

This is the highest priority incident. Assume the secret is compromised from the moment of detection.

1. **Immediately rotate** the exposed credential — revoke the key/token/password even if it appears unused
2. **Check commit history** — determine how long the secret has been in the repo using `git log`
3. **Remove from history** — use `git filter-branch` or BFG Repo Cleaner to purge the secret from all commits
4. **Force push** the cleaned history to GitLab (coordinate with Rutvik)
5. **Document** — log the incident in the Exception Log below with timeline and remediation steps
6. **Notify** — inform the team lead immediately; if this is a real project credential, notify the credential owner

#### 🔴 Critical or High Code Vulnerability (CODE-01 through CODE-07)

1. **Do not merge** — the pipeline gate has already blocked this; do not attempt to bypass it
2. **Identify the vulnerable code** — open the `gl-sast-report.json` artifact and locate the file and line number
3. **Remediate** — fix the vulnerability following the recommended action in `out/summary.md` (AI advisory) or standard secure coding guidance
4. **Re-push** — commit the fix to the same branch; the pipeline will re-run automatically
5. **Verify** — confirm the pipeline passes on the fixed commit before requesting a new review

#### 🔴 Critical Dependency CVE (DEP-01, DEP-02)

1. **Identify the vulnerable package** — check Trivy output for the CVE ID and affected version
2. **Upgrade the dependency** — update to the patched version in your dependency file
3. **If no patch exists** — document it as an exception with justification and seek team lead approval
4. **Re-scan** — push the updated dependency file and confirm the pipeline passes

#### 🟡 Medium or Low Finding (Any area)

1. **Log the finding** — add it to the Exception Log with the policy ID, finding summary, and date
2. **Assign ownership** — the developer who introduced the finding is responsible for remediation
3. **Set a review date** — medium findings within 48 hours, low findings within 1 week
4. **Track in next team sync** — bring to the next team standup for visibility

### 10.3 False Positive Process

If a finding is determined to be a false positive:

1. Document why it is a false positive (specific reasoning, not just "we think it's fine")
2. Get acknowledgement from one other team member in a GitLab MR comment
3. Add a suppression rule to the scanner config (coordinate with Yilu)
4. Log it in the Exception Log below with `False Positive` in the reason column
5. Re-scan to confirm the suppression works correctly

---

## 11. Exception Process & Log

### Exception Approval Requirements

| Severity | Who Must Approve | Maximum Duration |
|---|---|---|
| Critical | Team lead + documented justification | 7 days |
| High | Team lead acknowledgement | 14 days |
| Medium | Self-documented with peer review | 30 days |
| Low | Self-documented | 60 days |

All exceptions expire automatically. Expired exceptions require re-approval.

### Exception Log

| # | Date | Policy ID | Finding Summary | Reason | Type | Approved By | Expiry Date | Status |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — |

*Type options: `Accepted Risk` / `False Positive` / `Pending Remediation`*

---

## 12. Changelog

| Version | Date | Change | Author |
|---|---|---|---|
| 1.0 | 2026-03-10 | Initial policy registry created | Sakshi |
| 2.0 | 2026-04-22 | Added risk scoring matrix, pipeline enforcement map, AI governance policy, incident response procedures, expanded all policy areas, mapped to Rutvik's `.gitlab-ci.yml` | Sakshi |

---

*This document is version-controlled in the `Sakshi-Policyregistry` branch on GitLab. All changes must be committed with a descriptive commit message. Major changes require a merge request reviewed by at least one team member before merging to `main`.*
