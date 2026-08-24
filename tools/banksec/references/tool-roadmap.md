# Tool roadmap

| Phase | Tools | Purpose | Exit condition |
|---|---|---|---|
| POC | Trivy, Semgrep, SARIF converter, local policy | Prove normalization and scoring | Fixtures and policy tests pass |
| Shadow MVP | Dependabot, Snyk, Semgrep, Trivy adapters, Bedrock agents | Compare agent advice with analysts | No repository writes; measured precision |
| Controlled MVP | GitHub OIDC, protected environment, patch PRs | Generate review-only changes | Patch acceptance and rollback targets met |
| Production pilot | AgentCore, Guardrails, immutable evidence, GitHub App | Centralize governed execution | Security/model-risk approval and SLOs |
| Enterprise | Reusable workflows, policy service, CMDB/runtime context | Scale across approved repositories | Continuous control monitoring and audits |

## Scanner roles

| Tool | Best use | Output path |
|---|---|---|
| Semgrep | Fast custom rules and policy patterns | JSON normalized, then SARIF |
| Trivy | Dependencies, containers, IaC, secrets, SBOM-related scans | JSON normalized, then SARIF |
| Snyk | SCA, code, containers, IaC in teams already licensed | JSON adapter |
| Dependabot | GitHub-native vulnerable dependency alerts and upgrade PRs | Native alerts; use before custom patching |
| endoflife.date | Supplemental lifecycle evidence | Cache and validate; not an authority by itself |

Do not run every overlapping product merely to increase tool count. Select authoritative scanners per
language and artifact type, deduplicate by CVE/CWE/component/location, and define ownership.
