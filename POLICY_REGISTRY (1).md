# DevSecOps Security Policy Registry
**Project:** Secure DevSecOps Pipeline with Automated Security Controls  
**Owner:** Sakshi (Policy, Risk & Compliance Lead)  
**Framework:** NIST SP 800-53 (Rev 5)  
**Pipeline Platform:** GitLab CI/CD  
**Last Updated:** 2026-03-10  
**Status:** Active — v1.0

---

## How This Document Works

This registry defines every security policy enforced in the CI/CD pipeline.  
Each policy maps to:
- A specific area of risk (Code, Dependencies, Secrets, IaC)
- A NIST SP 800-53 control
- A severity level and gate action (Block or Warn)
- The scanner responsible for enforcement (fill in once Yilu confirms tools)

**Gate Actions:**
| Action | Meaning |
|---|---|
| 🔴 BLOCK | Pipeline fails. Merge request is blocked. Deployment cannot proceed. |
| 🟡 WARN | Pipeline passes with a warning. Finding is logged and must be reviewed. |
| 🟢 PASS | No issue detected. Pipeline continues normally. |

---

## Severity Thresholds

| Severity | Definition | Gate Action |
|---|---|---|
| **Critical** | Exploitable vulnerability, exposed secret, or misconfiguration with direct, immediate risk | 🔴 BLOCK |
| **High** | Significant vulnerability or misconfiguration that could be exploited with low effort | 🔴 BLOCK |
| **Medium** | Vulnerability or misconfiguration with limited exploitability or requiring specific conditions | 🟡 WARN |
| **Low** | Minor issue, best-practice deviation, or informational finding | 🟡 WARN |
| **Info** | Informational output only, no risk implication | 🟢 PASS |

---

## Area 1 — Code Security (SAST)

> Covers insecure code patterns identified through static analysis.

| Policy ID | Policy Name | Description | Severity | Gate Action | NIST Control | Enforced By |
|---|---|---|---|---|---|---|
| CODE-01 | No SQL Injection | Code must not contain patterns vulnerable to SQL injection attacks | Critical | 🔴 BLOCK | SI-10 (Input Validation) | TBD |
| CODE-02 | No Command Injection | Code must not pass unsanitized user input to system commands | Critical | 🔴 BLOCK | SI-10 (Input Validation) | TBD |
| CODE-03 | No Insecure Deserialization | Code must not deserialize untrusted data without validation | High | 🔴 BLOCK | SI-10 (Input Validation) | TBD |
| CODE-04 | No Hardcoded Credentials in Code | Source code must not contain passwords, tokens, or keys as literals | Critical | 🔴 BLOCK | IA-5 (Authenticator Mgmt) | TBD |
| CODE-05 | No Use of Deprecated Crypto | Code must not use MD5, SHA-1, or DES for security-sensitive operations | High | 🔴 BLOCK | SC-13 (Cryptographic Protection) | TBD |
| CODE-06 | No Unsafe Redirects | Code must validate all redirect URLs against an allowlist | Medium | 🟡 WARN | SI-10 (Input Validation) | TBD |
| CODE-07 | Error Handling Must Not Expose Stack Traces | Application errors must not return internal stack traces to users | Medium | 🟡 WARN | SI-11 (Error Handling) | TBD |
| CODE-08 | No Debug Code in Production | Debug flags, print statements exposing sensitive data must be removed | Low | 🟡 WARN | CM-6 (Config Settings) | TBD |

---

## Area 2 — Dependency Security (SCA)

> Covers known vulnerabilities in third-party libraries and packages.

| Policy ID | Policy Name | Description | Severity | Gate Action | NIST Control | Enforced By |
|---|---|---|---|---|---|---|
| DEP-01 | No Critical CVEs in Dependencies | No dependency may have a known CVE with CVSS score ≥ 9.0 | Critical | 🔴 BLOCK | RA-5 (Vulnerability Scanning) | TBD |
| DEP-02 | No High CVEs in Dependencies | No dependency may have a known CVE with CVSS score 7.0–8.9 | High | 🔴 BLOCK | RA-5 (Vulnerability Scanning) | TBD |
| DEP-03 | No Medium CVEs Without Review | Dependencies with CVSS 4.0–6.9 must be logged and reviewed | Medium | 🟡 WARN | RA-5 (Vulnerability Scanning) | TBD |
| DEP-04 | No Unpinned Dependency Versions | All dependencies must specify exact version numbers, not ranges | Medium | 🟡 WARN | CM-6 (Config Settings) | TBD |
| DEP-05 | No Abandoned Packages | Dependencies with no maintenance activity in 2+ years must be flagged | Low | 🟡 WARN | SA-22 (Unsupported Components) | TBD |
| DEP-06 | No Packages with Known License Violations | Dependencies must use OSI-approved licenses | Low | 🟡 WARN | SA-4 (Acquisition Process) | TBD |

---

## Area 3 — Secrets Detection

> Covers hardcoded secrets, tokens, keys, and credentials in source code or config files.

> ⚠️ **Zero Tolerance Policy:** Any secret detected anywhere in the codebase — regardless of whether it appears active — blocks deployment immediately. There are no warnings for secrets.

| Policy ID | Policy Name | Description | Severity | Gate Action | NIST Control | Enforced By |
|---|---|---|---|---|---|---|
| SEC-01 | No AWS Access Keys | No AWS access key IDs or secret keys in any file | Critical | 🔴 BLOCK | IA-5 (Authenticator Mgmt) | TBD |
| SEC-02 | No API Tokens or Bearer Tokens | No API tokens, bearer tokens, or OAuth secrets in any file | Critical | 🔴 BLOCK | IA-5 (Authenticator Mgmt) | TBD |
| SEC-03 | No Database Credentials | No database usernames, passwords, or connection strings in code | Critical | 🔴 BLOCK | IA-5 (Authenticator Mgmt) | TBD |
| SEC-04 | No Private Keys or Certificates | No private SSH keys, TLS certificates, or PEM files committed | Critical | 🔴 BLOCK | SC-12 (Key Management) | TBD |
| SEC-05 | No .env Files Committed | .env files containing environment variables must never be committed | Critical | 🔴 BLOCK | IA-5 (Authenticator Mgmt) | TBD |
| SEC-06 | No Generic High-Entropy Strings | Strings with entropy patterns matching credential format must be flagged | High | 🔴 BLOCK | IA-5 (Authenticator Mgmt) | TBD |

---

## Area 4 — Infrastructure as Code (IaC) Security

> Covers misconfigurations in Terraform, Kubernetes manifests, Dockerfiles, or cloud config files.

| Policy ID | Policy Name | Description | Severity | Gate Action | NIST Control | Enforced By |
|---|---|---|---|---|---|---|
| IAC-01 | No Publicly Accessible Storage Buckets | S3 buckets or equivalent must not have public read/write ACLs | Critical | 🔴 BLOCK | AC-3 (Access Enforcement) | TBD |
| IAC-02 | No Unrestricted Inbound Security Groups | Security groups must not allow 0.0.0.0/0 on sensitive ports (22, 3389, 5432) | Critical | 🔴 BLOCK | SC-7 (Boundary Protection) | TBD |
| IAC-03 | Encryption at Rest Required | All storage resources must have encryption enabled | High | 🔴 BLOCK | SC-28 (Protection at Rest) | TBD |
| IAC-04 | Encryption in Transit Required | All network resources must enforce TLS/HTTPS | High | 🔴 BLOCK | SC-8 (Transmission Confidentiality) | TBD |
| IAC-05 | No Root Account Usage | IAM configs must not use root account credentials or permissions | Critical | 🔴 BLOCK | AC-6 (Least Privilege) | TBD |
| IAC-06 | No Hardcoded IPs in Config | Infrastructure configs must not hardcode IP addresses | Medium | 🟡 WARN | CM-6 (Config Settings) | TBD |
| IAC-07 | Containers Must Not Run as Root | Dockerfiles and pod specs must specify a non-root user | High | 🔴 BLOCK | AC-6 (Least Privilege) | TBD |
| IAC-08 | No Latest Tag on Container Images | Container images must pin to a specific version tag, not `latest` | Medium | 🟡 WARN | CM-6 (Config Settings) | TBD |
| IAC-09 | Logging Must Be Enabled | All cloud resources must have logging/monitoring enabled | Medium | 🟡 WARN | AU-2 (Event Logging) | TBD |
| IAC-10 | MFA Must Be Enforced on IAM Users | All IAM user accounts must require MFA | High | 🔴 BLOCK | IA-2 (Identification & Auth) | TBD |

---

## NIST SP 800-53 Control Mapping Summary

| NIST Control | Control Name | Policies Mapped |
|---|---|---|
| AC-3 | Access Enforcement | IAC-01 |
| AC-6 | Least Privilege | IAC-05, IAC-07 |
| AU-2 | Event Logging | IAC-09 |
| CM-6 | Configuration Settings | CODE-08, DEP-04, IAC-06, IAC-08 |
| IA-2 | Identification & Authentication | IAC-10 |
| IA-5 | Authenticator Management | CODE-04, SEC-01, SEC-02, SEC-03, SEC-05, SEC-06 |
| RA-5 | Vulnerability Scanning | DEP-01, DEP-02, DEP-03 |
| SA-4 | Acquisition Process | DEP-06 |
| SA-22 | Unsupported System Components | DEP-05 |
| SC-7 | Boundary Protection | IAC-02 |
| SC-8 | Transmission Confidentiality | IAC-04 |
| SC-12 | Cryptographic Key Mgmt | SEC-04 |
| SC-13 | Cryptographic Protection | CODE-05 |
| SC-28 | Protection at Rest | IAC-03 |
| SI-10 | Information Input Validation | CODE-01, CODE-02, CODE-03, CODE-06 |
| SI-11 | Error Handling | CODE-07 |

---

## Exception Process

If a finding must be overridden (e.g., a known false positive), the following process applies:

1. **Document the finding** — Policy ID, scanner output, reason for exception
2. **Get approval** — Team lead must acknowledge the exception in writing (GitLab comment on MR)
3. **Set expiry** — Every exception expires after 30 days and must be re-reviewed
4. **Log it** — Add a row to the Exception Log below

### Exception Log

| Date | Policy ID | Finding Summary | Reason for Exception | Approved By | Expiry Date |
|---|---|---|---|---|---|
| — | — | — | — | — | — |

---

## Changelog

| Version | Date | Change | Author |
|---|---|---|---|
| 1.0 | 2026-03-10 | Initial policy registry created | Sakshi |

---

*This document is version-controlled in GitLab. All changes must be committed with a descriptive commit message and reviewed by the team lead before merging.*
