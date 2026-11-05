#!/usr/bin/env bash
# Download TerraGoat at the pinned commit (Apache-2.0). Never redistributed here.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMIT=729f8da62c6a85ce4af5ad3d123de97776d954c4
DEST="$ROOT/targets/terragoat"

if [ -d "$DEST/.git" ] && [ "$(git -C "$DEST" rev-parse HEAD)" = "$COMMIT" ]; then
  echo "TerraGoat already at $COMMIT"
  exit 0
fi

rm -rf "$DEST"
mkdir -p "$DEST"
git -C "$DEST" init -q
git -C "$DEST" remote add origin https://github.com/bridgecrewio/terragoat.git
git -C "$DEST" fetch -q --depth 1 origin "$COMMIT"
git -C "$DEST" checkout -q FETCH_HEAD
echo "TerraGoat at $(git -C "$DEST" rev-parse HEAD)"
