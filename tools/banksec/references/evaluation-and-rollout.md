# Evaluation and rollout

## POC: deterministic foundation

- Use synthetic repositories and fixture findings only.
- Prove every scanner adapter, score modifier, policy branch, SARIF field, and patch rejection path.
- Do not give the workflow AWS or repository write access.
- Exit when the same input always produces the same score/disposition and unsafe edits are rejected.

## MVP: shadow mode

- Invoke Bedrock on sanitized internal repositories, with `apply_patch=false`.
- Analysts independently label exploitability, recommended fix, and disposition before seeing output.
- Track false claims, missed controls, unsafe edits, useful proposals, cost, and latency.
- Freeze a representative benchmark and version prompts/models/policies.
- Exit only after model risk and application security approve measured thresholds.

Suggested starting thresholds, to be approved by the bank:

| Measure | Pilot gate |
|---|---:|
| Protected-path escape | 0 |
| Secret/customer-data disclosure | 0 |
| Policy bypass | 0 |
| Root-cause fix precision | >= 95% on eligible benchmark |
| Fixed test suite pass | 100% |
| Rescan clears target finding | 100% of accepted patches |
| Unrelated files changed | 0 |

## Controlled production pilot

- Permit PR creation in low-risk, non-customer-facing repositories.
- Keep human review, CODEOWNERS, fixed tests, rescan, signed evidence, and auto-merge prohibition.
- Start with dependency patch updates that have a vendor fix and no major-version migration.
- Add source-code edits only after a separate benchmark and approval.
- Roll back by disabling the environment or workflow and revoking the OIDC role.

## Enterprise production

- Central reusable workflows and a dedicated GitHub App.
- AgentCore versions promoted across isolated AWS accounts.
- Model/prompt/policy changes gated by offline evaluation and canary evidence.
- CMDB context, runtime reachability, asset criticality, data classification, and threat intelligence.
- Case-management integration, exception expiry, SLA tracking, and immutable audit evidence.
- Continuous red-team suites and incident response for harmful agent behavior.

