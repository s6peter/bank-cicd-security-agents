from banksec_agents.models import CanonicalFinding, Disposition, Location, Severity
from banksec_agents.policy import decide
from banksec_agents.risk import score_finding


def finding(**overrides):
    values = {
        "finding_id": "finding-123456",
        "scanner": "test",
        "rule_id": "TEST-1",
        "title": "test",
        "description": "test",
        "severity": Severity.MEDIUM,
        "cvss": 5.0,
        "fixed_version": "2.0.1",
        "location": Location(path="requirements.txt"),
    }
    values.update(overrides)
    return CanonicalFinding.create(**values)


def test_low_bounded_dependency_fix_is_auto_patch_candidate():
    item = finding(cvss=4.0)
    assessment = decide(item, score_finding(item))
    assert assessment.disposition == Disposition.AUTO_PATCH


def test_high_risk_requires_human_review():
    item = finding(cvss=8.2)
    assessment = decide(item, score_finding(item))
    assert assessment.disposition == Disposition.HUMAN_REVIEW


def test_missing_fix_is_deferred():
    item = finding(component="example-lib", fixed_version="")
    assessment = decide(item, score_finding(item))
    assert assessment.disposition == Disposition.DEFER


def test_protected_path_requires_human_review():
    item = finding(location=Location(path="src/payments/transfer.py"))
    assessment = decide(item, score_finding(item))
    assert assessment.disposition == Disposition.HUMAN_REVIEW

