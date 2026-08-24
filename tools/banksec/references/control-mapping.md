# Public control mapping

This is an engineering crosswalk, not a certification or legal opinion. Control owners must map it to
the bank's current internal policies and regulatory obligations.

| Engineering control | Public framework theme | Evidence |
|---|---|---|
| Versioned secure-development workflow | NIST SSDF PW/PS, FFIEC SDLC/change management | Workflow, review, tests |
| Deterministic risk and authority policy | NIST AI RMF Govern/Measure/Manage | Policy version and assessment JSON |
| Human approval and separation of duties | FFIEC governance/change control | Environment and PR approvals |
| OIDC and least privilege | NIST CSF Protect, zero standing credentials | IAM trust/policy and CloudTrail |
| SAST/SCA/IaC scans and rescans | NIST SSDF verification practices | Native output and SARIF |
| SBOM and provenance attestation | NIST SSDF/SLSA supply-chain practices | CycloneDX and attestation |
| Prompt-injection and protected-path gates | NIST AI 600-1 risk treatment | Adversarial tests and rejects |
| Hash-chained events and immutable export | Auditability and change traceability | JSONL chain and evidence archive |
| Rollback, canary, SLO, incident response | Operational resilience | Runbooks and exercise evidence |

Public references:

- NIST SP 800-218 Secure Software Development Framework
- NIST SP 800-218A generative AI and dual-use foundation model profile
- NIST AI Risk Management Framework and NIST AI 600-1 Generative AI Profile
- NIST Cybersecurity Framework 2.0
- FFIEC IT Examination Handbook and cloud computing statement
- GitHub supply-chain security, SARIF, OIDC, and artifact attestation documentation
- AWS Bedrock Guardrails and AgentCore security/observability documentation

