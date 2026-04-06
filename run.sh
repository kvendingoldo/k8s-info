#!/usr/bin/env bash
set -euo pipefail

LOG_LEVEL="${1:-INFO}"

pip install uv  --break-system-packages
uv venv
source .venv/bin/activate
uv pip install .
k8s-info --log-level "$LOG_LEVEL"  -o json -f out.json -H -P
