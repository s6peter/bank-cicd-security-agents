import json

from banksec_agents.audit import AuditLog
from banksec_agents.models import CanonicalFinding, Location
from banksec_agents.reporting import to_sarif


def test_sarif_is_2_1_0():
    finding = CanonicalFinding.create(
        finding_id="finding-123456",
        scanner="test",
        rule_id="TEST-1",
        title="Example",
        description="Example description",
        severity="high",
        location=Location(path="src/app.py", start_line=3, end_line=3),
    )
    result = to_sarif([finding])
    assert result["version"] == "2.1.0"
    location = result["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["region"]["startLine"] == 3


def test_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("one", {"ok": True})
    log.append("two", {"ok": True})
    assert log.verify()
    records = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(records[0])
    record["payload"]["ok"] = False
    records[0] = json.dumps(record)
    path.write_text("\n".join(records) + "\n", encoding="utf-8")
    assert not log.verify()
