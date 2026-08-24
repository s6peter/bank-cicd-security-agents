# GitHub Actions integration

## Two-workflow design

`security-scan.yml` runs on untrusted pull-request code with read-only repository access. It runs
Semgrep, Trivy, dependency review, tests, SBOM generation, and SARIF upload. It receives no AWS
credentials and cannot create a branch.

`security-remediate.yml` is manually dispatched from trusted default-branch code and is attached to a
protected GitHub environment. After approval, it exchanges GitHub's OIDC token for a short-lived AWS
role, invokes Bedrock, validates the patch, runs fixed tests, and opens a pull request. It never merges.

Do not combine these into a `pull_request_target` workflow that checks out untrusted PR code and then
uses secrets or write permissions.

## Required repository settings

1. Enable dependency graph, Dependabot alerts/security updates, secret scanning, push protection, and
   GitHub Code Security/Advanced Security features licensed for the repository.
2. Protect the default branch with required pull requests, conversation resolution, signed commits if
   organizationally required, and no force pushes.
3. Create rulesets requiring all application tests and security jobs.
4. Add CODEOWNERS for application areas plus `.github/workflows/`, `policies/`, and `infra/iam/`.
5. Create `security-remediation` as an environment with security-team reviewers and no self-review.
6. Restrict Actions to approved organizations and require full-length commit SHA pinning.
7. Store configuration in variables; do not store long-lived AWS keys.
8. Apply artifact retention consistent with investigation, legal hold, privacy, and record schedules.

## PR lifecycle

```text
scan -> normalize -> score -> policy -> Bedrock proposal -> independent review
     -> exact-edit validator -> fixed tests -> rescan -> agent-generated PR
     -> CODEOWNER/security review -> merge queue -> deployment approval
```

The remediation job must not execute model-generated shell commands. `proposal.tests` is advisory
metadata only. The workflow owns the actual commands.

## GHAS conversion

`banksec run` writes `banksec.sarif`, a SARIF 2.1.0 file accepted by GitHub code scanning. Upload each
scanner under a stable category so analyses do not overwrite one another. Preserve the native scanner
artifact for forensic detail and upload only sanitized, retention-approved evidence.

## SBOM and provenance

The scan workflow creates a CycloneDX JSON SBOM and attaches it to the build. On trusted pushes it
generates a GitHub SBOM attestation for the wheel. In a production application, generate the SBOM from
the final deployable container or package, not just the source directory, and verify the attestation at
the deployment admission gate.
