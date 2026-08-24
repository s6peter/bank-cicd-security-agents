"""Snapshot CISA KEV and mapped endoflife.date products for trusted CI.

Run this in a separate, egress-controlled workflow. Review and sign the output before a remediation
workflow consumes it. Runtime remediation itself should not depend on mutable public HTTP responses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_URL = "https://endoflife.date/api/{product}.json"


def get_json(url: str, retries: int = 3) -> Any:
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "banksec-catalog/0.1"})
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            if error.code < 500 or attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
        time.sleep(2**attempt)
    raise RuntimeError("unreachable")


def write_json(path: Path, value: Any) -> str:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    path.write_text(rendered, encoding="utf-8")
    return hashlib.sha256(rendered.encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product-map", default="config/product-map.json")
    parser.add_argument("--output-dir", default="intelligence")
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    product_map = json.loads(Path(args.product_map).read_text(encoding="utf-8"))
    eol = {
        product: get_json(EOL_URL.format(product=product))
        for product in set(product_map.values())
    }
    kev = get_json(KEV_URL)
    hashes = {
        "eol-catalog.json": write_json(output / "eol-catalog.json", eol),
        "cisa-kev.json": write_json(output / "cisa-kev.json", kev),
    }
    write_json(output / "manifest.json", {
        "generated_at": datetime.now(UTC).isoformat(),
        "sources": {"cisa_kev": KEV_URL, "endoflife_date": EOL_URL},
        "sha256": hashes,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
