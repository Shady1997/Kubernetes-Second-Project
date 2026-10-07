#!/usr/bin/env bash
set -euo pipefail
NS="trace-lab"
IMAGE="incident-lab:v5"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

guard(){
  need kubectl; need k3s; need docker
  kubectl cluster-info >/dev/null 2>&1 || die "kubectl cannot reach Kubernetes"
  echo "Context: $(kubectl config current-context 2>/dev/null || echo unknown)"
  echo "Cluster nodes:"
  kubectl get nodes --no-headers || true
  [[ "$NS" == "trace-lab" ]] || die "Safety guard failure"
}

build_import(){
  docker build -t "$IMAGE" "$ROOT"
  docker save "$IMAGE" | k3s ctr images import -
  k3s ctr images list | grep -E 'incident-lab.*v5' >/dev/null || die "K3s image import verification failed"
}

deploy(){
  kubectl apply -f "$ROOT/k8s/base.yaml"
  for d in customer-service session-service attestation-service legacy-service payment-service traffic-generator; do
    kubectl -n "$NS" rollout status "deployment/$d" --timeout=120s
  done
}

up(){
  guard
  build_import
  kubectl delete namespace "$NS" --ignore-not-found --wait=true
  deploy
  status
  echo
  echo "Recent customer IDs:"
  kubectl -n "$NS" logs -l app=customer-service --tail=30 | grep -o 'national_id="[^"]*"' | sort -u || true
}

status(){
  guard
  kubectl -n "$NS" get pods -o wide
  echo
  kubectl -n "$NS" get svc,endpoints
}

healthy(){
  guard
  kubectl delete namespace "$NS" --ignore-not-found --wait=true
  deploy
  status
}

scenarios(){ cat <<'LIST'
healthy
session-timeout
attestation-timeout
attestation-500
legacy-404
payment-timeout
no-endpoints
readiness-failure
crashloop
imagepull
missing-configmap
missing-secret
targetport-mismatch
networkpolicy-deny
oom
pvc-pending
LIST
}

scenario(){
  guard; name="${1:-}"
  [[ -n "$name" ]] || { scenarios; exit 2; }
  case "$name" in
    healthy) healthy ;;
    session-timeout) kubectl -n "$NS" set env deployment/session-service FAILURE_MODE=timeout ;;
    attestation-timeout) kubectl -n "$NS" set env deployment/attestation-service FAILURE_MODE=timeout ;;
    attestation-500) kubectl -n "$NS" set env deployment/attestation-service FAILURE_MODE=500 ;;
    legacy-404) kubectl -n "$NS" set env deployment/legacy-service FAILURE_MODE=404 ;;
    payment-timeout) kubectl -n "$NS" set env deployment/payment-service FAILURE_MODE=timeout ;;
    no-endpoints) kubectl -n "$NS" scale deployment/customer-service --replicas=0 ;;
    readiness-failure) kubectl -n "$NS" set env deployment/attestation-service FAILURE_MODE=readiness ;;
    crashloop) kubectl -n "$NS" patch deployment/session-service --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/command","value":["sh","-c","echo injected_crashloop >&2; exit 1"]}]' ;;
    imagepull) kubectl -n "$NS" patch deployment/legacy-service --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/image","value":"incident-lab:does-not-exist-v5"}]' ;;
    missing-configmap) kubectl -n "$NS" patch deployment/payment-service --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/env/4/valueFrom/configMapKeyRef/name","value":"missing-payment-config"}]' ;;
    missing-secret) kubectl -n "$NS" patch deployment/payment-service --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/env/3/valueFrom/secretKeyRef/name","value":"missing-payment-secret"}]' ;;
    targetport-mismatch) kubectl -n "$NS" patch service/attestation-service --type=json -p='[{"op":"replace","path":"/spec/ports/0/targetPort","value":9999}]' ;;
    networkpolicy-deny) cat <<'YAML' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-attestation
  namespace: trace-lab
spec:
  podSelector:
    matchLabels: {app: attestation-service}
  policyTypes: [Ingress]
  ingress: []
YAML
      ;;
    oom) kubectl -n "$NS" patch deployment/payment-service --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/command","value":["python","-c","x=[];\nwhile True: x.append(\"X\"*1048576)"]}]' ;;
    pvc-pending) cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: broken-pvc, namespace: trace-lab}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 10Gi}}
  storageClassName: definitely-missing-storage-class
YAML
      ;;
    *) die "Unknown scenario: $name. Run '$0 scenarios'." ;;
  esac
  echo "Scenario '$name' injected into namespace $NS."
}

reset(){ healthy; }
down(){ guard; kubectl delete namespace "$NS" --ignore-not-found --wait=true; echo "Only $NS was removed; K3s was not touched."; }

case "${1:-}" in
  up) up;; status) status;; scenarios) scenarios;; scenario) scenario "${2:-}";; reset) reset;; down) down;;
  *) echo "Usage: $0 {up|status|scenarios|scenario NAME|reset|down}"; exit 2;;
esac
