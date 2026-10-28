#!/usr/bin/env bash
# Idempotent setup for a Codespace (or any machine): sibling product checkout, one venv, and
# the dependencies the harness needs to run the product CLI and its real API on loopback.
# Touches no secrets and nothing outside /workspaces (or the parent of this repo).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(dirname "$HERE")"
PRODUCT="$PARENT/neuralbridge"
VENV="$PARENT/.venv"

if [ ! -d "$PRODUCT/.git" ]; then
  echo "cloning the product beside this repository: $PRODUCT"
  git clone https://github.com/iceccarelli/neuralbridge "$PRODUCT" || {
    echo "BLOCKED: could not clone iceccarelli/neuralbridge. In a Codespace this needs the repo" \
         "permission in .devcontainer/devcontainer.json (rebuild the Codespace), or run" \
         "'gh auth login' with access to both repositories." >&2
    exit 3
  }
else
  echo "product checkout present: $PRODUCT (left exactly as it is; this script never resets it)"
fi

[ -d "$VENV" ] || python3 -m venv "$VENV"
# shellcheck disable=SC1091
. "$VENV/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e "$HERE[dev]" httpx
python -m pip install --quiet -e "$PRODUCT[assurance-api]"

echo "product HEAD: $(git -C "$PRODUCT" rev-parse --short HEAD) ($(git -C "$PRODUCT" branch --show-current))"
echo
echo "ready. next:"
echo "  . $VENV/bin/activate && export NEURALBRIDGE_SRC=$PRODUCT/src"
echo "  python scripts/validate.py --api      # everything, including the real API on loopback"
