# Bank CI/CD Security Remediation Agents

A reference implementation for policy-controlled, multi-agent vulnerability remediation using
GitHub Actions, GitHub Advanced Security-compatible SARIF, CycloneDX SBOMs, Strands Agents, and
Amazon Bedrock.

This is a consulting baseline for a regulated financial institution. It is not Bank of America
software, does not represent Bank of America internal standards, and does not by itself establish
regulatory compliance. The bank's application security, model risk, legal, privacy, IAM, and change
management owners must approve the production control set.

## Rewritten requirement

Build an enterprise security-remediation service for a regulated bank that:

1. Ingests SARIF, Trivy, Semgrep, Snyk, and Dependabot findings.
2. Converts them to a canonical, versioned schema and GitHub code-scanning SARIF 2.1.0.
3. Enriches and ranks findings using deterministic risk policy, CVSS, exploit evidence,
   reachability, production exposure, sensitive-data impact, fix availability, and EOL status.
4. Uses separate Bedrock agents to interpret evidence, propose the smallest patch, independently
   review the patch, and produce audit-ready summaries.
5. Prevents models from changing policy, IAM, workflows, CODEOWNERS, secrets, or protected banking
   paths and prevents models from approving or merging their own work.
6. Applies only exact, bounded edits; runs an organization-owned test suite and rescans; then opens
   a review-only pull request with evidence, rollback instructions, and required approvals.
7. Produces CycloneDX SBOMs, signed build/SBOM attestations, normalized SARIF, test results, model
   metadata, and a tamper-evident audit chain.
8. Uses short-lived GitHub OIDC credentials, least-privilege Bedrock access, pinned GitHub Actions,
   protected environments, branch rules, CODEOWNERS, and separation of duties.

## Control flow

```text
Trivy / Semgrep / Snyk / Dependabot / SARIF
                    |
                    v
          Canonical finding schema
                    |
          +---------+----------+
          | deterministic      |
          | risk + policy gate |
          +---------+----------+
                    |
       +------------+-------------+
       | human review/defer/block |----> ticket + evidence
       +--------------------------+
                    |
              auto-patch eligible
                    v
   Interpreter -> Patch Engineer -> Independent Reviewer
                    |
          deterministic patch validator
                    |
       fixed tests + rescan + SBOM + attestation
                    |
          review-only pull request
                    |
     CODEOWNER + security + change approval
```

The LLM is inside the proposal path. It is never the policy engine, approval authority, merge
authority, deployment authority, or source of truth for test results.

## Main components

| Component | Purpose |
|---|---|
| `ingest.py` | Normalizes scanner-specific JSON and SARIF |
| `risk.py` | Calculates a reproducible 0-100 risk score |
| `policy.py` | Selects auto-patch, human review, defer, or block |
| `agents.py` | Defines four specialized Strands agents on Bedrock |
| `context.py` | Sends only bounded, allowlisted source context to the model |
| `patching.py` | Rejects unsafe paths, ambiguous edits, low confidence, and broad changes |
| `reporting.py` | Emits GitHub-compatible SARIF 2.1.0 |
| `audit.py` | Writes a hash-chained JSONL evidence log |
| `pipeline.py` | Runs the controlled end-to-end sequence |
| `.github/workflows/` | Read-only scans and manually approved remediation |
| `deploy/agentcore_app.py` | Optional read-only AgentCore Runtime endpoint |

## Run the deterministic demo

No AWS call or billable resource is used by these commands:

```bash
cd bank-cicd-security-agents
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,agentcore]'

banksec run \
  --scanner trivy \
  --scan fixtures/trivy.json \
  --repo . \
  --output-dir artifacts/demo

pytest
banksec verify-audit artifacts/demo/audit.jsonl
```

Inspect:

- `artifacts/demo/findings.json`: normalized findings
- `artifacts/demo/assessments.json`: risk and policy decisions
- `artifacts/demo/banksec.sarif`: GitHub Advanced Security input
- `artifacts/demo/audit.jsonl`: tamper-evident events
- `artifacts/demo/run-summary.json`: machine-readable run result

## Run with Amazon Bedrock

This invokes a model and incurs normal Bedrock inference charges. It creates no AgentCore runtime:

```bash
export AWS_DEFAULT_REGION=us-east-1
export BEDROCK_MODEL_ID=us.amazon.nova-pro-v1:0
aws sts get-caller-identity

banksec run \
  --scanner trivy \
  --scan fixtures/trivy.json \
  --repo . \
  --output-dir artifacts/bedrock \
  --use-bedrock
```

Add `--apply` only in a disposable branch or CI checkout. A proposal still must pass the independent
agent review and deterministic patch validator. This demo finding names a package not present in the
project, so a correct agent should produce no applicable edit.

## GitHub Actions rollout

1. Copy the project or package into the target repository.
2. Enable GitHub code scanning, dependency graph, Dependabot alerts, and branch rules.
3. Create the `security-remediation` GitHub environment with required security approvers.
4. Deploy the OIDC role in `infra/` after cloud-security review.
5. Add `BANKSEC_BEDROCK_ROLE_ARN`, `BANKSEC_AWS_REGION`, and `BANKSEC_MODEL_ID` as GitHub variables.
6. Require the scan workflow jobs and application test jobs as branch checks.
7. Run `Enterprise security scan` first. Start `Controlled Bedrock remediation` with
   `apply_patch=false` during shadow mode.
8. Permit patch PRs only after the evaluation thresholds in `references/evaluation-and-rollout.md`
   are met. Keep auto-merge disabled.

## Optional AgentCore deployment

AgentCore is useful when many repositories call one centrally governed analysis service. The endpoint
in this project is read-only: it accepts scanner JSON and returns interpretation. It has no GitHub
token, shell, or repository write access.

```bash
python deploy.py configure   # local files only; does not create an AWS runtime
python deploy.py launch      # creates billable AWS resources
python deploy.py invoke fixtures/trivy.json
python deploy.py teardown --delete-ecr-repo
```

Do not run `launch` until the IAM, networking, logging, retention, guardrail, and teardown design has
been approved. The starter toolkit is convenient for learning; production infrastructure should be
managed by the bank's approved IaC pipeline.

## Documentation

Start with `references/onboarding.md`, then read `references/architecture.md`,
`references/github-actions.md`, `references/bedrock-agentcore.md`, and
`references/evaluation-and-rollout.md`.
