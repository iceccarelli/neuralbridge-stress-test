#!/usr/bin/env bash
# Build the product's website from the product checkout's COMMITTED source, for the browser
# tests. Nothing in the product checkout is touched: the tree is exported with `git archive`
# into data/derived/site-build (Git-ignored), dependencies are installed there, and the site is
# built with the API address the browser tests use (http://127.0.0.1:18765, the product's own API
# on loopback). Needs: git, node >= 20, npm (registry.npmjs.org reachable).
#
#   bash scripts/build_site.sh [path-to-product-checkout]   (NEURALBRIDGE_REV=origin/main to build a fetched revision)
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
PRODUCT="${1:-${NEURALBRIDGE_SRC:+$(dirname "$NEURALBRIDGE_SRC")}}"
PRODUCT="${PRODUCT:-$LAB/../neuralbridge}"
[ -d "$PRODUCT/.git" ] || { echo "BLOCKED: $PRODUCT is not a product checkout" >&2; exit 2; }
OUT="$LAB/data/derived/site-build"
rm -rf "$OUT"; mkdir -p "$OUT"
REV="${NEURALBRIDGE_REV:-HEAD}"   # e.g. NEURALBRIDGE_REV=origin/main after `git fetch`
git -C "$PRODUCT" archive "$REV" | tar -x -C "$OUT"
git -C "$PRODUCT" rev-parse "$REV" > "$OUT/.product-sha"
cd "$OUT"
npm ci --no-audit --no-fund
NEXT_PUBLIC_ASSURANCE_API_URL="http://127.0.0.1:18765" npm run build
echo "built $(cat .product-sha) into $OUT"
