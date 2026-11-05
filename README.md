# iac-misconfig-hunter

[![CI](https://github.com/youssefbouaouina/iac-misconfig-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/youssefbouaouina/iac-misconfig-hunter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue)

How well do Checkov, Trivy, KICS and kube-linter find **35 known misconfigurations** in
deliberately vulnerable Terraform and Kubernetes code? This repository measures it, then fixes
the findings and enforces the fix in CI.

## Why

"I ran a scanner" is not a security result. The useful questions are: which scanner catches which
class of issue, what does each one miss, and does the fixed code actually stop being reported?
This repo answers those with a frozen ground truth and audit-friendly matching.

## Method

```mermaid
flowchart LR
  A[expected.yaml<br/>35 items, frozen first] --> D[compare]
  B[TerraGoat<br/>pinned commit] --> C[Checkov / Trivy / KICS]
  B2[15 K8s manifests] --> C
  B2 --> C2[kube-linter]
  C --> D
  C2 --> D
  D --> E[results/metrics.json<br/>recall + overlap]
  F[fixed/ Terraform] --> G[CI gate:<br/>fixed items gone + total down]
```

- **Ground truth:** `expected.yaml` lists 20 Terraform items and 15 Kubernetes items, each with
  file, resource and category. It was committed before the first scanner run.
- **Normalisation:** `mapping.yaml` maps each category to keywords. A finding counts only when it
  is on the expected file/resource and its title/message contains a keyword. Every match is
  written to `results/matches.csv` with the exact check, so the result can be audited.
- **Fixed set:** the AWS module is copied to `fixed/` and the 14 most severe findings are fixed.
  `scripts/gate.py` fails CI if any of those 14 is still reported or if the total findings did
  not go down.

## Results

CI run #5, 2026-11-05, from [`results/metrics.json`](results/metrics.json). TerraGoat pinned at
`729f8da62c6a85ce4af5ad3d123de97776d954c4`.

| Scanner | Terraform (20) | Kubernetes (15) | Findings (TF / K8s) |
|---|---|---|---|
| Checkov | 18/20 (90.0%) | 11/15 (73.3%) | 215 / 286 |
| Trivy | 15/20 (75.0%) | 15/15 (100.0%) | 115 / 247 |
| KICS | 17/20 (85.0%) | 12/15 (80.0%) | 155 / 337 |
| kube-linter | n/a | 11/15 (73.3%) | 0 / 70 |

- **34/35** items are found by at least one scanner; one Terraform item (a long-lived IAM access
  key, `TF14`) is missed by all four.
- All four scanners agree on **8** Kubernetes items. The full per-item matrix is in
  [`results/RESULTS.md`](results/RESULTS.md); every match is traceable in `results/matches.csv`.
- On the fixed Terraform module, **14/14 targeted findings are gone** and Checkov's total drops
  from **215 to 188**. CI fails if either number regresses.
- The comparison is recall on the same 35 items, not raw finding counts: the scanners have
  different rule granularity, so their totals are not directly comparable.

## Run

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt checkov==3.2.458
sudo apt install -y docker.io   # KICS runs as a container
bash scripts/scan_all.sh        # downloads TerraGoat, runs all four scanners
python scripts/gate.py
```

Or push: `.github/workflows/ci.yml` runs the same thing on Ubuntu with pinned tools.

## Limitations

- Keyword matching is a heuristic; the exact matches are in `matches.csv` and can be challenged.
- TerraGoat is a teaching target, not a production codebase.
- Finding counts are not directly comparable between scanners (different rule granularity);
  recall on the same 35 items is the comparable metric.
- Checkov's free JSON does not contain severity, so the gate is check-ID based, not "0 HIGH".
  This is stated instead of pretending a severity gate exists.

## Sources and licence

See [`SOURCES.md`](SOURCES.md). Code: MIT.

## Author

**Youssef Bouaouina** --- [github.com/youssefbouaouina](https://github.com/youssefbouaouina) --
[portfolio](https://youssefbouaouina.github.io/)

