"""Normalise the JSON output of Checkov, Trivy, KICS and kube-linter.

Every adapter returns a list of Finding objects with a common shape. Nothing in
this module reads the ground truth; it only transforms scanner output.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    scanner: str
    file: str
    resource: str
    line: int | None
    check: str
    message: str

    @property
    def text(self) -> str:
        return f"{self.check} {self.message}"


def _norm_path(value: str) -> str:
    return value.replace("\\", "/")


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _checkov(data) -> list[Finding]:
    if not data:
        return []
    # Checkov returns {"results": {...}} for one directory and a list of those
    # for several directories.
    blocks = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    for block in blocks:
        results = block.get("results", block) if isinstance(block, dict) else {}
        for check in results.get("failed_checks", []) or []:
            findings.append(
                Finding(
                    scanner="checkov",
                    file=_norm_path(str(check.get("file_path", ""))),
                    resource=str(check.get("resource", "")),
                    line=(check.get("file_line_range") or [None])[0],
                    check=str(check.get("check_name") or check.get("check_id") or ""),
                    message=str(check.get("check_id") or ""),
                )
            )
    return findings


def _trivy(data) -> list[Finding]:
    if not data:
        return []
    findings: list[Finding] = []
    for result in data.get("Results", []) or []:
        target = _norm_path(str(result.get("Target", "")))
        for item in result.get("Misconfigurations", []) or []:
            cause = item.get("CauseMetadata") or {}
            findings.append(
                Finding(
                    scanner="trivy",
                    file=target,
                    resource=str(cause.get("Resource", "")),
                    line=cause.get("StartLine"),
                    check=str(item.get("Title") or item.get("ID") or ""),
                    message=str(item.get("Message") or item.get("ID") or ""),
                )
            )
    return findings


def _kics(data) -> list[Finding]:
    if not data:
        return []
    findings: list[Finding] = []
    for query in data.get("queries", []) or []:
        for item in query.get("files", []) or []:
            findings.append(
                Finding(
                    scanner="kics",
                    file=_norm_path(str(item.get("file_name", ""))),
                    resource="",
                    line=item.get("line"),
                    check=str(query.get("query_name", "")),
                    message=str(query.get("query_id", "")),
                )
            )
    return findings


def _kube_linter(data) -> list[Finding]:
    if not data:
        return []
    findings: list[Finding] = []
    for report in data.get("Reports", []) or []:
        diagnostic = report.get("Diagnostic") or {}
        obj = report.get("Object") or {}
        k8s_obj = obj.get("K8sObject") or {}
        findings.append(
            Finding(
                scanner="kube-linter",
                file="",
                resource=str(k8s_obj.get("Name", "")),
                line=None,
                check=str(diagnostic.get("check", "")),
                message=str(diagnostic.get("message", "")),
            )
        )
    return findings


ADAPTERS = {
    "checkov": _checkov,
    "trivy": _trivy,
    "kics": _kics,
    "kube-linter": _kube_linter,
}


def parse(scanner: str, path: Path) -> list[Finding]:
    data = load(path)
    return ADAPTERS[scanner](data)


RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"')


def terraform_resources(path: Path) -> list[tuple[int, int, str]]:
    """Return (start_line, end_line, "type.name") for every Terraform resource."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    resources: list[tuple[int, int, str]] = []
    current: tuple[int, str] | None = None
    depth = 0
    for number, line in enumerate(lines, start=1):
        match = RESOURCE_RE.match(line)
        if match and current is None:
            current = (number, f"{match.group(1)}.{match.group(2)}")
            depth = line.count("{") - line.count("}")
            if depth <= 0:
                resources.append((number, number, current[1]))
                current = None
            continue
        if current:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                resources.append((current[0], number, current[1]))
                current = None
    return resources


def resource_at_line(root: Path, finding: Finding) -> str:
    """Resolve a Terraform resource name from a finding's file + line."""
    if finding.resource:
        return finding.resource
    if not finding.line:
        return ""
    # The scanner path can be absolute; try to find the file below root.
    rel = finding.file.split("targets/")[-1].split("tests/")[-1]
    candidates = [root / finding.file, root / rel]
    for candidate in candidates:
        if candidate.is_file():
            for start, end, name in terraform_resources(candidate):
                if start <= int(finding.line) <= end:
                    return name
    return ""
