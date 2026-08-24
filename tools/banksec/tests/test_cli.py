from banksec_agents.cli import main
from banksec_agents.models import RiskAssessment, Severity, write_json


def test_gate_passes_below_threshold(tmp_path):
    path = tmp_path / "assessments.json"
    assessment = RiskAssessment("finding-123456", 40, Severity.MEDIUM, ["test"])
    write_json(path, [assessment.to_dict()])
    assert main(["gate", "--assessments", str(path), "--fail-on", "high"]) == 0


def test_gate_fails_at_threshold(tmp_path):
    path = tmp_path / "assessments.json"
    assessment = RiskAssessment("finding-123456", 75, Severity.HIGH, ["test"])
    write_json(path, [assessment.to_dict()])
    assert main(["gate", "--assessments", str(path), "--fail-on", "high"]) == 1
