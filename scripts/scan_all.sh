#!/usr/bin/env bash
# Run all four scanners on the pinned targets. Linux only (KICS runs in Docker).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p results
bash scripts/fetch_targets.sh

TF=targets/terragoat/terraform/aws
K8S=tests/k8s

echo "== Checkov =="
checkov -d "$TF" --framework terraform -o json > results/checkov-terraform.json || true
checkov -d "$K8S" --framework kubernetes -o json > results/checkov-kubernetes.json || true

echo "== Trivy config =="
trivy config "$TF" --format json --quiet > results/trivy-terraform.json || true
trivy config "$K8S" --format json --quiet > results/trivy-kubernetes.json || true

echo "== KICS =="
rm -rf results/kics-tf results/kics-k8s
mkdir -p results/kics-tf results/kics-k8s
docker run --rm -v "$ROOT:/src" checkmarx/kics:v2.2.0 scan \
  -p "/src/$TF" -o /src/results/kics-tf --report-formats json --no-progress --silent || true
docker run --rm -v "$ROOT:/src" checkmarx/kics:v2.2.0 scan \
  -p "/src/$K8S" -o /src/results/kics-k8s --report-formats json --no-progress --silent || true
# KICS exits non-zero when it finds issues, so a missing report must fail here
# instead of silently producing a 0/0 result.
for kind in terraform kubernetes; do
  report=$(find "results/kics-$kind" -name '*.json' | head -n 1)
  if [ -z "$report" ]; then
    echo "KICS produced no report for $kind" >&2
    exit 1
  fi
  cp "$report" "results/kics-$kind.json"
done

echo "== kube-linter =="
kube-linter lint "$K8S" --format json > results/kube-linter-kubernetes.json || true

echo "== Fixed set (Checkov gate input) =="
checkov -d fixed --framework terraform -o json > results/checkov-fixed.json || true

python evaluate.py
