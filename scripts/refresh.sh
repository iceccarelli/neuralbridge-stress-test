#!/usr/bin/env bash
# One command to retest the product's current main. Safe to run repeatedly.
#
#   bash scripts/refresh.sh              # update ../neuralbridge-main, rebuild the site if needed, run the lab
#   bash scripts/refresh.sh --quick      # skip the slow browser/site tier
#
# It never touches any other product checkout, never resets, cleans or stashes, and never pushes.
set -uo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
PRODUCT="${NEURALBRIDGE_PRODUCT:-$LAB/../neuralbridge-main}"
URL="https://github.com/iceccarelli/neuralbridge.git"

if [ ! -d "$PRODUCT/.git" ]; then
  git clone --branch main "$URL" "$PRODUCT" || { echo "BLOCKED: could not clone $URL" >&2; exit 2; }
else
  git -C "$PRODUCT" fetch origin main || { echo "BLOCKED: could not fetch" >&2; exit 2; }
  git -C "$PRODUCT" checkout -q main
  git -C "$PRODUCT" merge --ff-only origin/main || { echo "BLOCKED: $PRODUCT has diverged from origin/main; use a fresh directory (NEURALBRIDGE_PRODUCT=...)" >&2; exit 2; }
fi
SHA="$(git -C "$PRODUCT" rev-parse HEAD)"
echo "product under test: $SHA"
export NEURALBRIDGE_SRC="$PRODUCT/src"

if [ "${1:-}" != "--quick" ]; then
  BUILT="$(cat "$LAB/data/derived/site-build/.product-sha" 2>/dev/null || true)"
  if [ "$BUILT" != "$SHA" ]; then
    echo "rebuilding the site for $SHA (was: ${BUILT:-none})"
    bash "$LAB/scripts/build_site.sh" "$PRODUCT" > "$LAB/data/derived/site-build.log" 2>&1 \
      && echo "site built" || echo "site build FAILED (see data/derived/site-build.log): browser tests will be BLOCKED"
  fi
fi

cd "$LAB"
LOG="$LAB/data/derived/last-run.log"; mkdir -p "$LAB/data/derived"
python -m pytest -q -rs -rX -p no:cacheprovider > "$LOG" 2>&1
CODE=$?
echo "----- result (full log: data/derived/last-run.log) -----"
tail -n 1 "$LOG"
echo "product: $SHA"
if grep -q "XPASS(strict)" "$LOG"; then
  echo "A KNOWN DEFECT APPEARS FIXED (a strict xfail now passes). Send me these lines:"
  grep -E "XPASS|FAILED.*XPASS" "$LOG" | head -20
fi
if [ $CODE -ne 0 ]; then
  echo "FAILURES (first 20):"; grep -E "^(FAILED|ERROR)" "$LOG" | head -20
fi
exit $CODE
