#!/usr/bin/env bash
set -euo pipefail
NS="${1:-trace-lab}"
SEARCH="${2:-}"
if [[ -z "$SEARCH" ]]; then
  echo "Usage: $0 <namespace> <national_id-or-correlation-id>"
  exit 2
fi
for pod in $(kubectl -n "$NS" get pods -o name); do
  echo "===== $pod ====="
  kubectl -n "$NS" logs "$pod" --all-containers --tail=5000 2>/dev/null | grep -F "$SEARCH" || true
done
