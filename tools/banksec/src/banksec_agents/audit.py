"""Tamper-evident JSONL audit records suitable for later export to immutable storage."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        previous_hash = self._last_hash()
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "run_id": os.getenv("GITHUB_RUN_ID", os.getenv("BANKSEC_RUN_ID", "local")),
            "event_type": event_type,
            "previous_hash": previous_hash,
            "payload": payload,
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["record_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def verify(self) -> bool:
        previous = "GENESIS"
        if not self.path.exists():
            return True
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                expected = record.pop("record_hash")
                if record["previous_hash"] != previous:
                    return False
                canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
                actual = hashlib.sha256(canonical.encode()).hexdigest()
                if actual != expected:
                    return False
                previous = expected
        return True

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        last = ""
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        return json.loads(last)["record_hash"] if last else "GENESIS"

