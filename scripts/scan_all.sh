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
rm -rf /tmp/kics-tf /tmp/kics-k8s
mkdir -p /tmp/kics-tf /tmp/kics-k8s
docker run --rm -v "$ROOT:/src" checkmarx/kics:v2.2.0 scan \
  -p /src/$TF -o /tmp/kics-tf --report-formats json --no-progress --silent || true
docker run --rm -v "$ROOT:/src" checkmarx/kics:v2.2.0 scan \
  -p /src/$K8S -o /tmp/kics-k8s --report-formats json --no-progress --silent || true
find /tmp/kics-tf -name '*.json' -exec cp {} results/kics-terraform.json \;
find /tmp/kics-k8s -name '*.json' -exec cp {} results/kics-kubernetes.json \;

echo "== kube-linter =="
kube-linter lint "$K8S" --format json > results/kubelinter-kubernetes.json || true

echo "== Fixed set (Checkov gate input) =="
checkov -d fixed --framework terraform -o json > results/checkov-fixed.json || true

python evaluate.py
