# Quick reference

```bash
# Tests and lint
ruff check .
pytest

# Deterministic scan conversion
banksec run --scanner trivy --scan trivy.json --repo . --output-dir artifacts/trivy
banksec run --scanner semgrep --scan semgrep.json --repo . --output-dir artifacts/semgrep
banksec run --scanner sarif --scan scanner-output.sarif --repo . --output-dir artifacts/sarif

# Deterministic enrichment from approved local feed snapshots
python scripts/refresh_intelligence.py --product-map config/product-map.json
banksec run --scanner trivy --scan trivy.json --repo . --output-dir artifacts/trivy \
  --eol-catalog intelligence/eol-catalog.json --product-map config/product-map.json \
  --kev-catalog intelligence/cisa-kev.json

# Bedrock proposal, no file write
banksec run --scanner trivy --scan trivy.json --repo . --output-dir artifacts/run --use-bedrock

# Bedrock proposal with controlled edits in current branch
banksec run --scanner trivy --scan trivy.json --repo . --output-dir artifacts/run --use-bedrock --apply

# Audit verification
banksec verify-audit artifacts/run/audit.jsonl

# AgentCore lifecycle; launch creates AWS resources and cost
python deploy.py configure
python deploy.py launch
python deploy.py invoke fixtures/trivy.json
python deploy.py teardown --delete-ecr-repo
```
