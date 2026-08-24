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
- GitHub dependency review
- SBOM and provenance evidence
- BankSec normalization, SARIF export, and policy gate

CodeQL and JFrog Xray are intentionally disabled.

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
