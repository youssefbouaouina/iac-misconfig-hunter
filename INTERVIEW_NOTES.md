# Interview notes — iac-misconfig-hunter

## What this project demonstrates

- Building a ground truth before running the tools (`expected.yaml` committed first), then
  matching findings to it by file, resource and category keywords — with every match dumped to
  `matches.csv` so a reviewer can disagree with a specific row.
- Knowing where the scanners differ: Trivy is strongest on the Kubernetes manifests, Checkov on
  the Terraform module, KICS in the middle, kube-linter intentionally limited to Kubernetes.
- Closing the loop: fixing 14 findings and gating both "the fixed items are gone" and "the total
  went down", so a new misconfiguration cannot hide behind a removed one.
- Working around a real limitation instead of inventing one: Checkov OSS JSON has no severity,
  so the gate is check-ID based.

## Questions I expect

**Why 35 items and not "all findings"?**
A finding count rewards a noisy scanner. A frozen list of known issues gives every scanner the
same denominator and makes misses visible. The list covers the classes TerraGoat is designed to
teach: public buckets, missing encryption/logging, open security groups, wildcard IAM, and the
usual pod-security mistakes.

**How do you avoid keyword matching being arbitrary?**
The mapping is a small YAML file (`mapping.yaml`), every category lists the keywords it accepts,
and the resulting match is written next to the raw check ID. If a match is wrong, it is one
editable row, not a hidden score. The limitation is stated in the README.

**Why is the gate not "zero high findings"?**
Checkov's free JSON does not carry severity. Trivy does, but using one scanner's severity to gate
all four would be misleading. The gate instead proves the 14 specific fixed findings are gone and
that the total went down, which is verifiable from the committed metrics.

**What did the scanners miss?**
`TF14` (long-lived IAM access key) is missed by all four. Several items are found by only one
scanner, which is the practical argument for running more than one tool — and for reading the
per-item matrix instead of trusting a single score.

**What would you change in production?**
Pin the target commit, run scanners in separate jobs with their native exit codes, keep raw JSON
as an artifact (this repo does), and add a diff gate against the previous run rather than a fixed
baseline. The fixed baseline is right for a teaching repo but would rot in a real codebase.
