"""Non-LLM approval policy for remediation decisions."""

from __future__ import annotations

import fnmatch
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from .models import CanonicalFinding, Disposition, RiskAssessment, Severity


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    if path:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    resource = files("banksec_agents").joinpath(
        "resources", "policies", "remediation-policy.json"
    )
    return json.loads(resource.read_text(encoding="utf-8"))


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def decide(
    finding: CanonicalFinding,
    assessment: RiskAssessment,
    policy: dict[str, Any] | None = None,
) -> RiskAssessment:
    policy = policy or load_policy()
    reasons: list[str] = []
    location = finding.location.path

    if finding.end_of_life:
        disposition = Disposition.HUMAN_REVIEW
        reasons.append("EOL replacements require an approved migration plan")
    elif finding.component and not finding.fixed_version:
        disposition = Disposition.DEFER
        reasons.append("No fixed package version is available; open a tracked exception")
    elif assessment.band in {Severity.CRITICAL, Severity.HIGH}:
        disposition = Disposition.HUMAN_REVIEW
        reasons.append("High and critical findings require security review")
    elif _matches_any(location, policy["protected_paths"]):
        disposition = Disposition.HUMAN_REVIEW
        reasons.append(f"{location or 'unknown path'} is protected by policy")
    elif finding.sensitive_data_path or finding.production_exposed:
        disposition = Disposition.HUMAN_REVIEW
        reasons.append("Customer-data or production exposure requires human approval")
    elif assessment.score <= int(policy["auto_patch"]["maximum_risk_score"]):
        disposition = Disposition.AUTO_PATCH
        reasons.append("Finding is inside the approved patch-only risk envelope")
    else:
        disposition = Disposition.HUMAN_REVIEW
        reasons.append("Finding exceeds the automatic patch threshold")

    assessment.disposition = disposition
    assessment.policy_reasons = reasons
    return assessment
