"""Canonical contracts exchanged between scanners, agents, and policy gates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Disposition(StrEnum):
    AUTO_PATCH = "auto_patch"
    HUMAN_REVIEW = "human_review"
    DEFER = "defer"
    BLOCK = "block"


@dataclass(slots=True)
class Location:
    path: str = ""
    start_line: int = 1
    end_line: int = 1


@dataclass(slots=True)
class CanonicalFinding:
    finding_id: str
    scanner: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    cvss: float | None = None
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    component: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    package_type: str = ""
    location: Location = field(default_factory=Location)
    references: list[str] = field(default_factory=list)
    exploit_known: bool = False
    reachable: bool | None = None
    end_of_life: bool = False
    production_exposed: bool = False
    sensitive_data_path: bool = False
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def create(cls, **values: Any) -> CanonicalFinding:
        values["severity"] = normalize_severity(values.get("severity"))
        if isinstance(values.get("location"), dict):
            values["location"] = Location(**values["location"])
        if not values.get("finding_id"):
            stable = "|".join(
                str(values.get(key, ""))
                for key in ("scanner", "rule_id", "component", "installed_version")
            )
            stable += f"|{getattr(values.get('location'), 'path', '')}"
            values["finding_id"] = hashlib.sha256(stable.encode()).hexdigest()[:20]
        return cls(**values)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CanonicalFinding:
        return cls.create(**value)

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        if not include_raw:
            value.pop("raw", None)
        return value


@dataclass(slots=True)
class RiskAssessment:
    finding_id: str
    score: int
    band: Severity
    reasons: list[str]
    disposition: Disposition = Disposition.HUMAN_REVIEW
    policy_reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RiskAssessment:
        return cls(
            finding_id=value["finding_id"],
            score=int(value["score"]),
            band=Severity(value["band"]),
            reasons=list(value.get("reasons", [])),
            disposition=Disposition(value.get("disposition", "human_review")),
            policy_reasons=list(value.get("policy_reasons", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["band"] = self.band.value
        value["disposition"] = self.disposition.value
        return value


@dataclass(slots=True)
class Edit:
    path: str
    original: str
    replacement: str
    rationale: str


@dataclass(slots=True)
class PatchProposal:
    finding_id: str
    summary: str
    confidence: float
    edits: list[Edit]
    tests: list[str]
    residual_risk: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PatchProposal:
        return cls(
            finding_id=value["finding_id"],
            summary=value["summary"],
            confidence=float(value["confidence"]),
            edits=[Edit(**edit) for edit in value.get("edits", [])],
            tests=list(value.get("tests", [])),
            residual_risk=list(value.get("residual_risk", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_severity(value: Any) -> Severity:
    text = str(value or "medium").lower()
    aliases = {"warning": "medium", "error": "high", "note": "low", "unknown": "medium"}
    text = aliases.get(text, text)
    return Severity(text) if text in Severity._value2member_map_ else Severity.MEDIUM


def read_json(path: str | Path) -> Any:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | Path, value: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
