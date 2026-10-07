# Incident Scenarios

| Scenario | Expected Kubernetes/application symptom |
|---|---|
| healthy | Normal end-to-end trace |
| attestation-timeout | Downstream timeout and correlation chain stops/backs up at attestation |
| attestation-500 | HTTP 500 from attestation |
| legacy-404 | Legacy lookup returns record-not-found |
| payment-timeout | Payment hop becomes slow/unavailable |
| session-timeout | Session hop times out |
| no-endpoints | customer-service has zero replicas/endpoints |
| readiness-failure | attestation pod remains NotReady |
| crashloop | session container exits immediately |
| imagepull | legacy deployment references nonexistent image |
| missing-configmap | payment pod cannot resolve required ConfigMap |
| missing-secret | payment pod cannot resolve required Secret |
| targetport-mismatch | Service points at an invalid target port |
| networkpolicy-deny | Ingress to attestation is denied |
| oom | payment process intentionally exceeds memory limit |
| pvc-pending | PVC requests a nonexistent storage class |

After every incident:

    kubectl -n trace-lab get pods
    kubectl -n trace-lab get events --sort-by=.lastTimestamp
    kubectl -n trace-lab get svc,endpoints
    kubectl -n trace-lab logs <pod> --previous
    kubectl -n trace-lab describe pod <pod>

Then correlate the application IDs from the customer trace.
