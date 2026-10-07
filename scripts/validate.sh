#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash -n "$ROOT/scripts/lab.sh" "$ROOT/scripts/find-trace.sh" "$ROOT/scripts/show-chain.sh"
python3 -m py_compile "$ROOT/app/service.py" "$ROOT/app/traffic.py"
if grep -R -E 'kind create|kind-' "$ROOT/scripts" --exclude=validate.sh >/dev/null; then
  echo 'ERROR: kind dependency remains'
  exit 1
fi
grep -q 'incident-lab:v5' "$ROOT/k8s/base.yaml"
grep -q 'k3s ctr' "$ROOT/scripts/lab.sh"
echo 'Static validation: OK'
