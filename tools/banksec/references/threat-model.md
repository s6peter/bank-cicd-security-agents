# Threat model

## Assets

Source code, scanner findings, model prompts/responses, GitHub write tokens, AWS role sessions, policies,
SBOMs, build artifacts, customer-data indicators, audit evidence, and reviewer identities.

## Principal threats and controls

| Threat | Control |
|---|---|
| Malicious PR injects instructions into code/comments | No AWS credentials in PR scan; untrusted-data prompt boundary |
| Model edits CI to gain authority | `never_modify`, excluded Git add paths, CODEOWNERS, branch rules |
| Model hides finding instead of fixing it | No suppressions, independent review, rescan, fixed tests |
| Scanner text performs prompt injection | Canonicalization, no tools, structured output, adversarial tests |
| Agent leaks source/secrets | Bounded context, secret scanning/redaction, no external model/network tools |
| Compromised Action changes workflow | Full SHA pins, Actions allowlist, Dependabot review |
| Long-lived cloud credential stolen | GitHub OIDC, environment-bound trust, one-hour session |
| Agent self-approves or merges | No auto-merge; required human/CODEOWNER/security approval |
| Audit record modified | Hash chain and production immutable evidence export |
| Unsafe dependency upgrade breaks system | Fixed tests, lockfile review, no major upgrade auto-patch |
| Model/provider drift changes behavior | Frozen eval set, versioned model/prompt, promotion gates |
| Denial of wallet or runaway calls | Finding and patch caps, token limits, concurrency, budgets/alarms |

## Residual risks

An LLM can produce a plausible but incorrect patch, tests can be incomplete, scanners can miss issues,
and a valid SARIF conversion does not prove a finding is correct. Human review and defense in depth
remain required.

