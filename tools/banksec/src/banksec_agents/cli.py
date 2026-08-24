"""Command-line interface used locally and by GitHub Actions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .models import CanonicalFinding, RiskAssessment, read_json, write_json
from .pipeline import RemediationPipeline
from .reporting import to_sarif


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="banksec", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="normalize, score, export SARIF, and optionally patch")
    run.add_argument(
        "--scanner",
        required=True,
        choices=["trivy", "semgrep", "sarif", "snyk", "dependabot"],
    )
    run.add_argument("--scan", required=True)
    run.add_argument("--repo", default=".")
    run.add_argument("--output-dir", default="artifacts")
    run.add_argument("--policy")
    run.add_argument("--use-bedrock", action="store_true")
    run.add_argument("--apply", action="store_true")
    run.add_argument("--maximum-patches", type=int, default=1)
    run.add_argument("--eol-catalog")
    run.add_argument("--product-map")
    run.add_argument("--kev-catalog")

    export = sub.add_parser("to-sarif", help="convert canonical JSON to enriched SARIF")
    export.add_argument("--findings", required=True)
    export.add_argument("--assessments")
    export.add_argument("--output", required=True)

    verify = sub.add_parser("verify-audit", help="verify the audit log hash chain")
    verify.add_argument("path")

    gate = sub.add_parser("gate", help="fail CI when assessed risk meets a threshold")
    gate.add_argument("--assessments", required=True)
    gate.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "run":
        pipeline = RemediationPipeline(
            repo=args.repo,
            output_dir=args.output_dir,
            policy_path=args.policy,
            use_bedrock=args.use_bedrock,
            eol_catalog_path=args.eol_catalog,
            product_map_path=args.product_map,
            kev_catalog_path=args.kev_catalog,
        )
        summary = pipeline.run(
            scanner=args.scanner,
            scan_path=args.scan,
            apply=args.apply,
            maximum_patches=args.maximum_patches,
        )
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "to-sarif":
        findings = [CanonicalFinding.from_dict(item) for item in read_json(args.findings)]
        assessments = {}
        if args.assessments:
            assessments = {
                item.finding_id: item
                for item in (RiskAssessment.from_dict(raw) for raw in read_json(args.assessments))
            }
        write_json(args.output, to_sarif(findings, assessments))
        return 0

    if args.command == "verify-audit":
        valid = AuditLog(Path(args.path)).verify()
        print("valid" if valid else "invalid")
        return 0 if valid else 1
    if args.command == "gate":
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        assessments = [RiskAssessment.from_dict(item) for item in read_json(args.assessments)]
        blocked = [item for item in assessments if rank[item.band.value] >= rank[args.fail_on]]
        if blocked:
            print(json.dumps([item.to_dict() for item in blocked], indent=2))
            return 1
        print(f"gate passed: no findings at or above {args.fail_on}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
