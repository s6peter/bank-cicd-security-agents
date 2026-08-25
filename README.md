# Enterprise Multi-Language Voting App + BankSec CI/CD

This repository is organized as an enterprise-style monorepo. It contains:

- a sample multi-language voting application under `services/`
- the reusable BankSec CI/CD security remediation framework under `tools/banksec/`
- GitHub Actions workflows under `.github/workflows/`
- shared scanner and remediation policy under `config/` and `policies/`

The sample app asks: **What is your favorite season?**

## Layout

```text
.
├── .github/
│   ├── workflows/
│   │   ├── security-scan.yml
│   │   └── security-remediate.yml
│   └── dependabot.yml
├── config/
│   └── semgrep.yml
├── policies/
│   └── remediation-policy.json
├── services/
│   ├── api-python/       # Flask API that stores votes
│   ├── web-node/         # Node/Express web UI
│   └── worker-go/        # Go worker that reads vote totals
├── tools/
│   └── banksec/          # CI/CD security agent framework
└── docker-compose.yml
```

## Services

| Service | Language | Purpose |
|---|---|---|
| `services/api-python` | Python / Flask | REST API for options, votes, results |
| `services/web-node` | Node.js / Express | Browser UI and API proxy |
| `services/worker-go` | Go | Background worker that logs vote totals |
| `db` | Postgres | Stores vote records |

## Run Locally

```bash
docker compose up --build
```

Open:

```text
http://localhost:3100
```

Useful endpoints:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/options
curl http://localhost:8000/results
curl -X POST http://localhost:8000/votes \
  -H 'content-type: application/json' \
  -d '{"season":"summer"}'
```

Stop and remove the database volume:

```bash
docker compose down -v
```

## Security Pipeline

The pull-request security workflow scans this multi-language repo with:

- Semgrep matrix jobs for `python`, `javascript-typescript`, `go`, and `node`
- Trivy filesystem/dependency scanning across the full repo
- GitHub dependency review (public repos / GHAS only — see below)
- SBOM and provenance evidence
- BankSec normalization, SARIF export, and policy gate

CodeQL and JFrog Xray are intentionally disabled.

### Controls degraded on a private repo without GHAS

Some GitHub-native controls require the Dependency Graph and GitHub Advanced
Security, which are not available on a private repository without a GHAS
licence. Rather than fail every pull request, the workflow skips them:

| Control | State | Compensating control |
| --- | --- | --- |
| `dependency-review` job | Skipped while the repo is private | Trivy filesystem scan covers dependency CVEs |
| Deny GPL-3.0 / AGPL-3.0 licences | **Not enforced** | None — no substitute licence gate is configured |
| SARIF upload to code scanning | Best-effort (`continue-on-error`) | SARIF is retained as a build artifact for 30 days |
| SBOM attestation | Push events on public repos only | SBOM still generated and uploaded as an artifact |

Each of these re-enables automatically if the repository is made public or a
GHAS licence is applied — no workflow change required. The licence-denial gap
is the only one with no substitute today; close it with a dedicated licence
scanner if that control is required.

## BankSec Tooling

Run the deterministic BankSec demo:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e './tools/banksec[dev,agentcore]'

banksec run \
  --scanner trivy \
  --scan tools/banksec/fixtures/trivy.json \
  --repo . \
  --output-dir artifacts/demo

pytest tools/banksec/tests
banksec verify-audit artifacts/demo/audit.jsonl
```

The remediation workflow is intentionally separate and manually approved. The pull-request workflow
does not receive AWS credentials.
