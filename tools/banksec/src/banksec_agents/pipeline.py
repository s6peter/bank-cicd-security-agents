"""Deterministic orchestration around optional Bedrock specialist agents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .agents import SecurityAgentTeam
from .audit import AuditLog
from .context import collect_context
from .enrichment import enrich_findings
from .ingest import normalize
from .models import (
    CanonicalFinding,
    Disposition,
    RiskAssessment,
    read_json,
    write_json,
)
from .patching import ControlledPatchApplier, PatchRejected
from .policy import decide, load_policy
from .reporting import to_sarif
from .risk import score_finding


class RemediationPipeline:
    def __init__(
        self,
        repo: str | Path,
        output_dir: str | Path = "artifacts",
        policy_path: str | Path | None = None,
        use_bedrock: bool = False,
        eol_catalog_path: str | Path | None = None,
        product_map_path: str | Path | None = None,
        kev_catalog_path: str | Path | None = None,
    ) -> None:
        self.repo = Path(repo).resolve()
        self.output_dir = Path(output_dir).resolve()
        self.policy = load_policy(policy_path)
        self.policy_path = policy_path
        self.audit = AuditLog(self.output_dir / "audit.jsonl")
        self.team = SecurityAgentTeam() if use_bedrock else None
        self.eol_catalog = read_json(eol_catalog_path) if eol_catalog_path else None
        self.product_map = read_json(product_map_path) if product_map_path else None
        self.kev_catalog = read_json(kev_catalog_path) if kev_catalog_path else None

    def analyze(
        self,
        scanner: str,
        scan_path: str | Path,
    ) -> tuple[list[CanonicalFinding], list[RiskAssessment]]:
        document = read_json(scan_path)
        findings = normalize(scanner, document)
        enrichment = enrich_findings(
            findings,
            eol_catalog=self.eol_catalog,
            product_map=self.product_map,
            kev_catalog=self.kev_catalog,
        )
        assessments = [decide(finding, score_finding(finding), self.policy) for finding in findings]
        self.audit.append("scan_normalized", {
            "scanner": scanner,
            "finding_count": len(findings),
            "source": str(scan_path),
            "enrichment": enrichment,
        })
        write_json(self.output_dir / "findings.json", [item.to_dict() for item in findings])
        write_json(self.output_dir / "assessments.json", [item.to_dict() for item in assessments])
        indexed = {item.finding_id: item for item in assessments}
        write_json(self.output_dir / "banksec.sarif", to_sarif(findings, indexed))
        return findings, assessments

    def remediate(
        self,
        finding: CanonicalFinding,
        assessment: RiskAssessment,
        apply: bool = False,
    ) -> dict[str, Any]:
        outcome: dict[str, Any] = {
            "finding_id": finding.finding_id,
            "disposition": assessment.disposition.value,
            "applied": False,
        }
        if assessment.disposition != Disposition.AUTO_PATCH:
            outcome["reason"] = "Policy does not permit automatic patch generation"
            self.audit.append("remediation_skipped", outcome)
            return outcome
        if self.team is None:
            outcome["reason"] = "Bedrock was not enabled; deterministic analysis is complete"
            self.audit.append("remediation_skipped", outcome)
            return outcome

        context = collect_context(self.repo, finding)
        opinion = self.team.interpret(finding, assessment, context)
        proposal = self.team.propose_patch(finding, assessment, opinion, context)
        if proposal.finding_id != finding.finding_id:
            raise PatchRejected("Patch agent returned the wrong finding ID")
        review = self.team.review(finding, assessment, proposal, context)
        if not review.approved:
            outcome.update({
                "reason": "Independent patch-review agent rejected proposal",
                "review": review.model_dump(),
            })
            self.audit.append("patch_rejected", outcome)
            return outcome

        applier = ControlledPatchApplier(self.repo, self.policy_path)
        changed = applier.apply(proposal, dry_run=not apply)
        write_json(self.output_dir / f"patch-{finding.finding_id}.json", proposal.to_dict())
        outcome.update({
            "applied": apply,
            "dry_run": not apply,
            "changed_files": changed,
            "tests": sorted(set(proposal.tests + review.required_tests)),
            "proposal": proposal.to_dict(),
            "triage": opinion.model_dump(),
            "review": review.model_dump(),
        })
        self.audit.append("patch_applied" if apply else "patch_validated", {
            key: value for key, value in outcome.items() if key != "proposal"
        })
        return outcome

    def run(
        self,
        scanner: str,
        scan_path: str | Path,
        apply: bool = False,
        maximum_patches: int = 1,
    ) -> dict[str, Any]:
        findings, assessments = self.analyze(scanner, scan_path)
        assessment_by_id = {item.finding_id: item for item in assessments}
        candidates = sorted(
            (
                finding
                for finding in findings
                if assessment_by_id[finding.finding_id].disposition == Disposition.AUTO_PATCH
            ),
            key=lambda item: assessment_by_id[item.finding_id].score,
            reverse=True,
        )[:maximum_patches]
        remediations = [
            self.remediate(finding, assessment_by_id[finding.finding_id], apply)
            for finding in candidates
        ]
        summary = {
            "scanner": scanner,
            "total_findings": len(findings),
            "dispositions": {
                disposition.value: sum(1 for item in assessments if item.disposition == disposition)
                for disposition in Disposition
            },
            "remediations": remediations,
        }
        write_json(self.output_dir / "run-summary.json", summary)
        return summary


def load_findings_and_assessments(
    findings_path: str | Path,
    assessments_path: str | Path,
) -> tuple[list[CanonicalFinding], list[RiskAssessment]]:
    findings = [CanonicalFinding.from_dict(item) for item in read_json(findings_path)]
    assessments = [RiskAssessment.from_dict(item) for item in read_json(assessments_path)]
    return findings, assessments
