from pathlib import Path

from banksec_agents.context import collect_context
from banksec_agents.models import CanonicalFinding, Location
from banksec_agents.pipeline import RemediationPipeline, load_findings_and_assessments

ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_writes_evidence_without_bedrock(tmp_path):
    output = tmp_path / "artifacts"
    pipeline = RemediationPipeline(repo=ROOT, output_dir=output)
    summary = pipeline.run("trivy", ROOT / "fixtures" / "trivy.json")
    assert summary["total_findings"] == 1
    assert summary["dispositions"]["auto_patch"] == 1
    assert (output / "banksec.sarif").is_file()
    assert pipeline.audit.verify()
    findings, assessments = load_findings_and_assessments(
        output / "findings.json", output / "assessments.json"
    )
    assert findings[0].finding_id == assessments[0].finding_id


def test_context_is_bounded_and_line_numbered(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("\n".join(f"line_{index}" for index in range(150)), encoding="utf-8")
    finding = CanonicalFinding.create(
        finding_id="finding-123456",
        scanner="test",
        rule_id="TEST",
        title="test",
        description="test",
        severity="medium",
        location=Location(path="src/app.py", start_line=75, end_line=75),
    )
    context = collect_context(tmp_path, finding)
    assert "src/app.py" in context
    assert "75: line_74" in context["src/app.py"]
    assert "1: line_0" not in context["src/app.py"]


def test_context_rejects_path_escape(tmp_path):
    finding = CanonicalFinding.create(
        finding_id="finding-123456",
        scanner="test",
        rule_id="TEST",
        title="test",
        description="test",
        severity="medium",
        location=Location(path="../secret.txt"),
    )
    assert collect_context(tmp_path, finding) == {}
