# Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `No module named banksec_agents` | Project not installed in active venv | Activate `.venv`; run `pip install -e '.[dev,agentcore]'` |
| Bedrock `AccessDeniedException` | Model access, Region, IAM, or inference profile mismatch | Check `aws sts get-caller-identity`, Region, role policy, and model access |
| No patch proposal | Finding is outside auto-patch policy or context lacks an exact target | Inspect `assessments.json` and source location |
| `Expected one exact match` | Model replacement is ambiguous or stale | Reject it; rerun from current commit or patch manually |
| SARIF upload rejected | Invalid path/schema, oversized result, or GHAS unavailable | Validate SARIF 2.1.0 and repository licensing/settings |
| OIDC role cannot be assumed | Trust subject does not match repository environment | Match org, repo, audience, and `security-remediation` environment |
| PR step has no changes | Reviewer rejected proposal or dry-run selected | Inspect run summary and audit artifact |
| AgentCore launch creates resources unexpectedly | `launch` was used rather than `configure` | Run teardown; review runtime, ECR, build project, roles, and logs |

Never “fix” a blocked remediation by weakening policy or manually adding broader workflow permissions.

