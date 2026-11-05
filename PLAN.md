# PLAN — iac-misconfig-hunter

## Goal
Measure how well four open-source IaC scanners find 35 known misconfigurations, then fix the
10 most severe Terraform findings and enforce the fix in CI.

## Targets
- **Terraform:** TerraGoat, pinned commit `729f8da` (Apache-2.0), AWS subset only (`terraform/aws`).
- **Kubernetes:** 15 deliberately vulnerable manifests written for this repo (`tests/k8s/`).

## Ground truth
`expected.yaml`: 20 Terraform items and 15 Kubernetes items, each (file, resource, category).
Written by reading the source before any scanner ran, and committed before the first run.

## Scanners (pinned)
- Checkov (pip)
- Trivy config (binary)
- KICS (binary)
- kube-linter (Kubernetes only)

## Normalisation
`mapping.yaml` maps every ground-truth category to keywords. A finding counts for an item when
it is on the same file or resource and its check title/message contains a keyword. The matched
check IDs are written to `results/matches.csv` so the matching can be audited, not trusted.

## Metrics
- Per-scanner recall on Terraform (20 items) and Kubernetes (15 items).
- Total findings per scanner (noise).
- Overlap table (which scanners found each item).
- Fixed set: Checkov HIGH count before/after, CI gate `--hard-fail-on HIGH` on `fixed/`.

## Time box
2-3 hours. KICS is Linux-only, so the full four-scanner run happens in GitHub Actions; Checkov
and Trivy are also run locally while developing.
