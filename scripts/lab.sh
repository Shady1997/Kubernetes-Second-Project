#!/usr/bin/env bash
set -euo pipefail
CLUSTER="${LAB_CLUSTER:-incident-debug-lab}"
NS="trace-lab"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1"; exit 1; }; }
require kubectl
require kind
require docker

use_lab_context() {
  kubectl config use-context "kind-${CLUSTER}" >/dev/null
}

up() {
  if ! kind get clusters | grep -qx "$CLUSTER"; then
    kind create cluster --name "$CLUSTER"
  fi
  use_lab_context
  docker build -t incident-lab:v4 "$ROOT"
  kind load docker-image incident-lab:v4 --name "$CLUSTER"
  kubectl apply -f "$ROOT/k8s/base.yaml"
  kubectl -n "$NS" rollout status deployment/customer-service --timeout=120s
  kubectl -n "$NS" rollout status deployment/session-service --timeout=120s
  kubectl -n "$NS" rollout status deployment/attestation-service --timeout=120s
  kubectl -n "$NS" rollout status deployment/legacy-service --timeout=120s
  kubectl -n "$NS" rollout status deployment/payment-service --timeout=120s
  kubectl -n "$NS" rollout status deployment/traffic-generator --timeout=120s
  echo "Lab is running."
}

healthy() {
  kubectl config use-context "kind-${CLUSTER}" >/dev/null
  kubectl -n "$NS" delete networkpolicy --all --ignore-not-found
  kubectl -n "$NS" delete deployment broken-no-endpoints broken-imagepull broken-crashloop broken-oom broken-pvc --ignore-not-found
  kubectl -n "$NS" delete pod -l app=broken-readiness --ignore-not-found
  kubectl -n "$NS" delete configmap broken-config --ignore-not-found
  kubectl -n "$NS" delete secret broken-secret --ignore-not-found
  for s in customer-service session-service attestation-service legacy-service payment-service; do
    kubectl -n "$NS" set env deployment/"$s" FAILURE_MODE=none DELAY_MS=0
    kubectl -n "$NS" rollout restart deployment/"$s"
  done
  kubectl -n "$NS" apply -f "$ROOT/k8s/base.yaml" >/dev/null
  echo "Baseline restored."
}

setmode() {
  local svc="$1" mode="$2"
  kubectl -n "$NS" set env deployment/"$svc" FAILURE_MODE="$mode"
  kubectl -n "$NS" rollout status deployment/"$svc" --timeout=90s || true
}

scenario() {
  case "${1:-}" in
    healthy) healthy ;;
    attestation-timeout) setmode attestation-service timeout ;;
    attestation-500) setmode attestation-service 500 ;;
    legacy-404) setmode legacy-service 404 ;;
    payment-timeout) setmode payment-service timeout ;;
    session-timeout) setmode session-service timeout ;;
    no-endpoints) kubectl -n "$NS" scale deployment/customer-service --replicas=0; echo "customer-service now has zero endpoints" ;;
    readiness-failure) setmode attestation-service readiness ;;
    crashloop)
      kubectl -n "$NS" patch deployment session-service --type='json' -p='[{"op":"replace","path":"/spec/template/spec/containers/0/command","value":["sh","-c","echo injected_crashloop >&2; exit 1"]}]'
      ;;
    imagepull)
      kubectl -n "$NS" patch deployment legacy-service --type='json' -p='[{"op":"replace","path":"/spec/template/spec/containers/0/image","value":"incident-lab:does-not-exist"}]'
      ;;
    missing-configmap)
      kubectl -n "$NS" patch deployment payment-service --type='json' -p='[{"op":"replace","path":"/spec/template/spec/containers/0/env/1/valueFrom/configMapKeyRef/name","value":"missing-payment-config"}]'
      ;;
    missing-secret)
      kubectl -n "$NS" patch deployment payment-service --type='json' -p='[{"op":"replace","path":"/spec/template/spec/containers/0/env/0/valueFrom/secretKeyRef/name","value":"missing-payment-secret"}]'
      ;;
    targetport-mismatch)
      kubectl -n "$NS" patch service attestation-service --type='json' -p='[{"op":"replace","path":"/spec/ports/0/targetPort","value":9999}]'
      ;;
    networkpolicy-deny)
      cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-attestation
  namespace: trace-lab
spec:
  podSelector:
    matchLabels:
      app: attestation-service
  policyTypes: ["Ingress"]
  ingress: []
EOF
      ;;
    oom)
      kubectl -n "$NS" patch deployment payment-service --type='json' -p='[{"op":"replace","path":"/spec/template/spec/containers/0/command","value":["python","-c","x=[]\nwhile True: x.append('X'*1048576)"]}]'
      ;;
    pvc-pending)
      cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: broken-pvc
  namespace: trace-lab
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 10Gi
  storageClassName: definitely-missing-storage-class
EOF
      ;;
    *) echo "Unknown scenario. Run: $0 scenario <name>"; exit 2 ;;
  esac
}

status() {
  kubectl config use-context "kind-${CLUSTER}" >/dev/null
  kubectl -n "$NS" get pods -o wide
  kubectl -n "$NS" get svc,endpoints
}

reset() { healthy; kubectl -n "$NS" get pods; }
down() { kind delete cluster --name "$CLUSTER"; }

case "${1:-}" in
  up) up ;;
  status) status ;;
  scenario) scenario "${2:-}" ;;
  reset) reset ;;
  down) down ;;
  *) echo "Usage: $0 {up|status|scenario NAME|reset|down}"; exit 2 ;;
esac
