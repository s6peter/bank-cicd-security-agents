from pathlib import Path

import pytest

from banksec_agents.ingest import normalize
from banksec_agents.models import read_json

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.parametrize(
    ("scanner", "filename", "rule_id"),
    [
        ("trivy", "trivy.json", "CVE-2024-TEST-0001"),
        ("semgrep", "semgrep.json", "python.lang.security.audit.dynamic-exec"),
        ("dependabot", "dependabot.json", "GHSA-TEST-1234-5678"),
    ],
)
def test_normalizes_supported_scanners(scanner, filename, rule_id):
    findings = normalize(scanner, read_json(FIXTURES / filename))
    assert len(findings) == 1
    assert findings[0].rule_id == rule_id
    assert findings[0].finding_id


def test_stable_finding_id():
    document = read_json(FIXTURES / "trivy.json")
    first = normalize("trivy", document)[0]
    second = normalize("trivy", document)[0]
    assert first.finding_id == second.finding_id
