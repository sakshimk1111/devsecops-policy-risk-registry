# devsecops-policy-risk-registry
Policy, risk scoring, and NIST SP 800-53 mapping for a team DevSecOps capstone (AWS, GitLab CI/CD). My contribution: the governance layer.

# DevSecOps Policy & Risk Registry

Governance documentation I authored for a team capstone project at Worcester Polytechnic Institute: a CI/CD security pipeline built on AWS and GitLab CI/CD.

## My role

I was the **Policy, Risk & Compliance Lead** on a [number]-person team. This repo contains only my deliverable. The pipeline code itself was built by my teammates and is not included here.

| Area | Owner |
|---|---|
| Policy registry, risk scoring, control mapping, AI governance, incident response procedures | **Me** |
| Scanner integration | [Teammate name] |
| Pipeline configuration | [Teammate name] |

## What's in the registry

[`POLICY_REGISTRY.md`](./POLICY_REGISTRY.md) covers:

- **Policies:** [30+ / confirm count] policies across code security, secrets management, dependency management, and infrastructure-as-code
- **Risk scoring model:** how findings are rated and which severities block a deployment
- **Control mapping:** findings mapped to NIST SP 800-53 [and CIS Controls, if applicable]
- **AI governance:** rules for the Amazon Bedrock advisory layer that summarizes scan results, so AI-generated triage stays reviewable by a human
- **Incident response procedures:** [one line on what these cover]

## About the pipeline

The team's pipeline integrated SAST (Semgrep), secrets detection (Gitleaks), and IaC scanning (Checkov) with severity-based policy gates. This was an academic project, not a production system.

## Context

Team capstone, M.S. Cybersecurity, Worcester Polytechnic Institute, [semester/year].

## Contact

Sakshi Kulkarni | [LinkedIn](https://linkedin.com/in/sakshi-makarand-kulkarni)
