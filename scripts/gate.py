#!/usr/bin/env python3
"""CI gate for the fixed Terraform set.

Checkov's open-source JSON does not include severity (that field needs a Prisma
Cloud API key), so a literal "0 HIGH" gate would be dishonest. Instead this gate
asserts the strongest thing the free output supports:

  * none of the ground-truth findings that were fixed is still reported by Checkov
  * the total number of Checkov findings on fixed/ is lower than on the original

The second condition stops a "fix" that just moves problems around.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import evaluate  # noqa: E402
import scanner  # noqa: E402
RESULTS = ROOT / "results"
FIXED_IDS = [
    "TF01", "TF02", "TF03", "TF04", "TF05", "TF06", "TF07",
    "TF08", "TF09", "TF10", "TF11", "TF12", "TF13", "TF15",
]


def count_findings(path: Path) -> int:
    data = scanner.load(path) or {}
    results = data.get("results", data) if isinstance(data, dict) else {}
    return len(results.get("failed_checks", []) or [])


def main() -> int:
    expected = evaluate.load_yaml(ROOT / "expected.yaml")
    mapping = evaluate.load_yaml(ROOT / "mapping.yaml")["categories"]
    items = {item["id"]: item for item in expected["items"]}
    fixed_findings = scanner.parse("checkov", RESULTS / "checkov-fixed.json")

    failures = []
    for item_id in FIXED_IDS:
        item = items[item_id]
        keywords = mapping[item["category"]]
        hit = next((f for f in fixed_findings if evaluate.item_found(item, f, keywords)), None)
        if hit:
            failures.append(f"{item_id} still reported: {hit.check} on {hit.resource or hit.file}")

    before = count_findings(RESULTS / "checkov-terraform.json")
    after = count_findings(RESULTS / "checkov-fixed.json")
    if after >= before:
        failures.append(f"fixed/ has {after} findings, original has {before}: no improvement")

    print(f"Checkov findings: original={before} fixed={after}")
    print(f"Fixed ground-truth findings: {len(FIXED_IDS) - len(failures)}/{len(FIXED_IDS)} clean")
    for failure in failures:
        print("GATE FAIL:", failure)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
