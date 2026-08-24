"""Read-only AgentCore endpoint for scanner interpretation and patch proposals."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from banksec_agents.agents import SecurityAgentTeam
from banksec_agents.ingest import normalize
from banksec_agents.policy import decide
from banksec_agents.risk import score_finding

app = BedrockAgentCoreApp()
team = SecurityAgentTeam()


@app.entrypoint
def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    scanner = payload.get("scanner")
    scan = payload.get("scan")
    if not scanner or not isinstance(scan, dict):
        return {"error": "Payload requires 'scanner' and a scanner JSON object in 'scan'."}
    findings = normalize(scanner, scan)
    context = payload.get("source_context") or {}
    output = []
    for finding in findings[: int(payload.get("maximum_findings", 10))]:
        assessment = decide(finding, score_finding(finding))
        opinion = team.interpret(finding, assessment, context)
        output.append({
            "finding": finding.to_dict(include_raw=False),
            "assessment": assessment.to_dict(),
            "interpretation": opinion.model_dump(),
        })
    return {"findings": output, "truncated": len(findings) > len(output)}


if __name__ == "__main__":
    app.run()
