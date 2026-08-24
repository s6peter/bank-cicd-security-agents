# Environment setup

## Prerequisites

- Python 3.11 or 3.12
- Git 2.40+
- AWS CLI v2 with an approved development profile
- GitHub CLI for local PR experiments
- Docker only when reproducing Trivy locally
- Bedrock model access in the selected AWS Region

## Local installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev,agentcore]'
pytest
```

## Environment variables

| Variable | Required | Purpose |
|---|---:|---|
| `AWS_DEFAULT_REGION` | Bedrock only | AWS SDK Region; default is `us-east-1` |
| `BEDROCK_MODEL_ID` | Bedrock only | Approved model/inference profile ID |
| `BEDROCK_MAX_TOKENS` | No | Per-agent response ceiling; default 5000 |
| `BANKSEC_RUN_ID` | No | Local correlation ID; GitHub uses `GITHUB_RUN_ID` |
| `BANKSEC_BEDROCK_ROLE_ARN` | GitHub | Repository variable used by OIDC workflow |

Never store AWS access keys, GitHub PATs, customer data, source secrets, or production scan payloads in
`.env` files. GitHub Actions uses OIDC and temporary AWS credentials.

## Verification

```bash
ruff check .
pytest --cov=banksec_agents --cov-report=term-missing
banksec run --scanner trivy --scan fixtures/trivy.json --repo . --output-dir artifacts/demo
banksec verify-audit artifacts/demo/audit.jsonl
```

