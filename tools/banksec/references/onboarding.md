# Onboarding

This project turns heterogeneous security findings into controlled remediation proposals. The fastest
way to understand it is to run the no-AWS demo and inspect each artifact in order.

## First hour

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,agentcore]'
pytest
banksec run --scanner trivy --scan fixtures/trivy.json --repo . --output-dir artifacts/demo
```

Read these files in order:

1. `src/banksec_agents/ingest.py`: scanner adapters.
2. `src/banksec_agents/risk.py`: risk math.
3. `src/banksec_agents/policy.py`: authority decision.
4. `src/banksec_agents/agents.py`: Bedrock specialist boundaries.
5. `src/banksec_agents/patching.py`: exact-edit enforcement.
6. `.github/workflows/security-remediate.yml`: CI authority and PR creation.

## Learning exercise

Change the fixture CVSS from `5.9` to `8.9`, rerun the pipeline, and observe that the disposition moves
to human review. Then change the location to `src/payments/transfer.py`; policy should require human
review even at medium risk. These are code controls, not prompt behavior.

