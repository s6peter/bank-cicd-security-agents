"""AgentCore helper. Only `launch` creates billable AWS resources.

Commands:
    python deploy.py configure
    python deploy.py launch
    python deploy.py invoke fixtures/trivy.json
    python deploy.py teardown --delete-ecr-repo
"""

from __future__ import annotations

import json
import sys

from bedrock_agentcore_starter_toolkit import Runtime

AGENT_NAME = "banksec_remediation_agent"


def runtime() -> Runtime:
    configured = Runtime()
    configured.configure(
        entrypoint="deploy/agentcore_app.py",
        agent_name=AGENT_NAME,
        requirements_file="requirements-agentcore.txt",
        auto_create_execution_role=True,
        region="us-east-1",
    )
    return configured


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "configure"
    instance = runtime()
    if command == "configure":
        print("Configured locally. No runtime was created.")
    elif command == "launch":
        print(instance.launch())
    elif command == "invoke":
        with open(sys.argv[2], encoding="utf-8") as handle:
            scan = json.load(handle)
        print(instance.invoke(payload={"scanner": "trivy", "scan": scan}))
    elif command == "teardown":
        print(instance.destroy(delete_ecr_repo="--delete-ecr-repo" in sys.argv))
    else:
        raise SystemExit(f"Unknown command: {command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

