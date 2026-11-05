#!/usr/bin/env python3
"""Compute scanner recall against the frozen ground truth.

Inputs
  expected.yaml       35 (file, resource, category) items, committed before any scan
  mapping.yaml        category -> keywords
  results/<scanner>-<target>.json
  results/checkov-fixed.json (optional, for the fixed-set gate)

Outputs
  results/metrics.json
  results/RESULTS.md
  results/matches.csv
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

import scanner

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

SCANNERS = ["checkov", "trivy", "kics", "kube-linter"]
TARGETS = ["terraform", "kubernetes"]


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def file_matches(expected: str, found: str) -> bool:
    if not found:
        return False
    expected = expected.replace("\\", "/")
    found = found.replace("\\", "/")
    if found == expected or found.endswith("/" + expected) or found.endswith(expected):
        return True
    # Checkov reports paths relative to the scanned directory ("/s3.tf"), so the
    # basename is the only stable part. Filenames in the scanned subsets are unique.
    return found.rsplit("/", 1)[-1] == expected.rsplit("/", 1)[-1]


def resource_matches(expected: str, found: str) -> bool:
    if not found:
        return False
    if found == expected or found.endswith(expected):
        return True
    return found.split(".")[-1] == expected.split(".")[-1]


def item_found(item: dict, finding: scanner.Finding, keywords: list[str]) -> bool:
    if item["target"] == "kubernetes":
        # kube-linter has no file in its JSON, only the object name.
        if finding.file:
            if not file_matches(item["file"], finding.file):
                return False
        elif not resource_matches(item["resource"], finding.resource):
            return False
    else:
        if not file_matches(item["file"], finding.file):
            return False
        resolved = finding.resource or (
            scanner.resource_at_line(ROOT, finding) if finding.line else ""
        )
        if resolved and not resource_matches(item["resource"], resolved):
            return False
    text = finding.text.lower()
    return any(keyword.lower() in text for keyword in keywords)


def evaluate() -> dict:
    expected = load_yaml(ROOT / "expected.yaml")
    mapping = load_yaml(ROOT / "mapping.yaml")["categories"]
    items = expected["items"]

    findings: dict[tuple[str, str], list[scanner.Finding]] = {}
    for name in SCANNERS:
        for target in TARGETS:
            path = RESULTS / f"{name}-{target}.json"
            findings[(name, target)] = scanner.parse(name, path) if path.exists() else []

    rows = []
    matches = []
    for item in items:
        keywords = mapping[item["category"]]
        found_by = []
        for name in SCANNERS:
            target_findings = findings[(name, item["target"])]
            hit = next((f for f in target_findings if item_found(item, f, keywords)), None)
            if hit:
                found_by.append(name)
                matches.append(
                    {
                        "item": item["id"],
                        "scanner": name,
                        "check": hit.check,
                        "file": hit.file,
                        "resource": hit.resource,
                        "line": hit.line,
                    }
                )
        rows.append({**item, "found_by": found_by, "found": bool(found_by)})

    scanners_metrics = {}
    for name in SCANNERS:
        per_target = {}
        for target in TARGETS:
            subset = [row for row in rows if row["target"] == target]
            if target == "kubernetes" or name != "kube-linter":
                detected = sum(1 for row in subset if name in row["found_by"])
                per_target[target] = {
                    "detected": detected,
                    "total": len(subset),
                    "recall": round(detected / len(subset), 4) if subset else None,
                    "findings": len(findings[(name, target)]),
                }
            else:
                per_target[target] = {
                    "detected": 0,
                    "total": len(subset),
                    "recall": None,
                    "findings": 0,
                }
        scanners_metrics[name] = per_target

    overlap: dict[str, int] = {}
    for row in rows:
        key = "+".join(row["found_by"]) if row["found_by"] else "none"
        overlap[key] = overlap.get(key, 0) + 1

    fixed = {"high_before": None, "high_after": None, "total_after": None}
    fixed_path = RESULTS / "checkov-fixed.json"
    if fixed_path.exists():
        fixed_findings = scanner.parse("checkov", fixed_path)
        high = 0
        for check in scanner.load(fixed_path).get("results", {}).get("failed_checks", []) or []:
            if str(check.get("severity", "")).upper() == "HIGH":
                high += 1
        fixed["high_after"] = high
        fixed["total_after"] = len(fixed_findings)

    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "terragoat_commit": expected["terragoat_commit"],
        "items_total": len(items),
        "scanners": scanners_metrics,
        "overlap": dict(sorted(overlap.items(), key=lambda pair: (-pair[1], pair[0]))),
        "items": rows,
        "matches": matches,
        "fixed": fixed,
    }


def write(metrics: dict) -> None:
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    with (RESULTS / "matches.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["item", "scanner", "check", "file", "resource", "line"]
        )
        writer.writeheader()
        writer.writerows(metrics["matches"])

    tf_total = sum(1 for row in metrics["items"] if row["target"] == "terraform")
    k8s_total = sum(1 for row in metrics["items"] if row["target"] == "kubernetes")
    lines = [
        "# Results — iac-misconfig-hunter",
        "",
        f"Generated by `python evaluate.py` at {metrics['generated_at']} (UTC).",
        f"TerraGoat pinned at `{metrics['terragoat_commit']}`.",
        "",
        "## Recall",
        "",
        f"| Scanner | Terraform ({tf_total}) | Kubernetes ({k8s_total}) | Findings (TF / K8s) |",
        "|---|---|---|---|",
    ]
    for name, per_target in metrics["scanners"].items():
        tf = per_target["terraform"]
        k8s = per_target["kubernetes"]
        tf_cell = (
            f"{tf['detected']}/{tf['total']} ({tf['recall']:.1%})"
            if tf["recall"] is not None
            else "n/a"
        )
        k8s_cell = (
            f"{k8s['detected']}/{k8s['total']} ({k8s['recall']:.1%})"
            if k8s["recall"] is not None
            else "not applicable"
        )
        lines.append(
            f"| {name} | {tf_cell} | {k8s_cell} | {tf['findings']} / {k8s['findings']} |"
        )

    lines += [
        "",
        "## Overlap",
        "",
        "| Scanners that found the item | Items |",
        "|---|---|",
    ]
    for combo, count in metrics["overlap"].items():
        lines.append(f"| {combo} | {count} |")

    lines += [
        "",
        "## Per item",
        "",
        "| ID | Target | Resource | Category | Found by |",
        "|---|---|---|---|---|",
    ]
    for row in metrics["items"]:
        found = ", ".join(row["found_by"]) if row["found_by"] else "—"
        lines.append(
            f"| {row['id']} | {row['target']} | `{row['resource']}` | {row['category']} | {found} |"
        )

    if metrics["fixed"]["high_after"] is not None:
        lines += [
            "",
            "## Fixed set",
            "",
            f"`fixed/` Checkov HIGH findings: **{metrics['fixed']['high_after']}** "
            f"(total findings: {metrics['fixed']['total_after']}).",
        ]

    lines += [
        "",
        "## Reproduction",
        "",
        "```bash",
        "bash scripts/fetch_targets.sh",
        "bash scripts/scan_all.sh",
        "python evaluate.py",
        "```",
        "",
        "Matching is keyword-based (`mapping.yaml`). Every match is listed in",
        "`results/matches.csv`",
        "with the scanner check that produced it, so the numbers can be audited line by line.",
        "",
    ]
    (RESULTS / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    metrics = evaluate()
    write(metrics)
    print(
        "items:", metrics["items_total"],
        "| checkov TF/K8s:", metrics["scanners"]["checkov"]["terraform"]["detected"],
        "/", metrics["scanners"]["checkov"]["kubernetes"]["detected"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
