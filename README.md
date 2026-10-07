# Kubernetes Production Incident / Trace-Correlation Lab v4

A disposable Kubernetes lab designed to practice production-style incident investigation and
customer trace correlation across multiple pods.

## What this lab actually generates

A request starts with:

    national_id
       -> flow_id
       -> session_id
       -> attestation_id
       -> original_id

Those IDs are deliberately passed between different services/pods and written to logs.

Service chain:

    traffic-generator
          |
          v
    customer-service
          |
          v
    session-service
          |
          v
    attestation-service
          |
          v
    legacy-service
          |
          v
    payment-service

Example log:

    level=INFO event=customer_received national_id=784512345678 flow_id=FLOW-a12bc3

    level=INFO event=session_created national_id=784512345678 flow_id=FLOW-a12bc3 session_id=SES-91ef22

    level=INFO event=attestation_created flow_id=FLOW-a12bc3 session_id=SES-91ef22 attestation_id=ATT-71ac04

    level=ERROR event=legacy_lookup_failed flow_id=FLOW-a12bc3 session_id=SES-91ef22 attestation_id=ATT-71ac04 original_id=ORG-88c201 error=record_not_found

This makes the lab suitable for testing a scanner that starts with a customer/national ID,
discovers correlation IDs, searches other pods, and reconstructs a chronological trace.

## Prerequisites

- Docker
- kind
- kubectl
- Bash
- Internet access the first time images are pulled/built if Docker does not already have them.
- A Linux shell, WSL, Git Bash, or similar environment for scripts.

The lab is intended for a disposable kind cluster named `incident-debug-lab`.
Do NOT point these scripts at a production cluster.

## Start

    ./scripts/lab.sh up

The command creates a kind cluster, builds the service image, loads it into kind,
and deploys the complete chain.

Then:

    ./scripts/lab.sh status
    kubectl -n trace-lab get pods -o wide
    kubectl -n trace-lab get svc

Watch logs:

    kubectl -n trace-lab logs -l app=customer-service --tail=50
    kubectl -n trace-lab logs -l app=session-service --tail=50
    kubectl -n trace-lab logs -l app=attestation-service --tail=50
    kubectl -n trace-lab logs -l app=legacy-service --tail=50
    kubectl -n trace-lab logs -l app=payment-service --tail=50

## Find a national ID

    kubectl -n trace-lab logs -l app=customer-service --tail=100

Then search that ID across every pod:

    kubectl -n trace-lab logs -l app=customer-service --all-containers --tail=5000 | grep -F '784512345678'
    kubectl -n trace-lab logs -l app=session-service --all-containers --tail=5000 | grep -F '784512345678'
    kubectl -n trace-lab logs -l app=attestation-service --all-containers --tail=5000 | grep -F '784512345678'
    kubectl -n trace-lab logs -l app=legacy-service --all-containers --tail=5000 | grep -F '784512345678'
    kubectl -n trace-lab logs -l app=payment-service --all-containers --tail=5000 | grep -F '784512345678'

## Failure scenarios

Each scenario changes ONLY the disposable lab namespace.

    ./scripts/lab.sh scenario healthy
    ./scripts/lab.sh scenario attestation-timeout
    ./scripts/lab.sh scenario attestation-500
    ./scripts/lab.sh scenario legacy-404
    ./scripts/lab.sh scenario payment-timeout
    ./scripts/lab.sh scenario session-timeout
    ./scripts/lab.sh scenario no-endpoints
    ./scripts/lab.sh scenario readiness-failure
    ./scripts/lab.sh scenario crashloop
    ./scripts/lab.sh scenario imagepull
    ./scripts/lab.sh scenario missing-configmap
    ./scripts/lab.sh scenario missing-secret
    ./scripts/lab.sh scenario targetport-mismatch
    ./scripts/lab.sh scenario networkpolicy-deny
    ./scripts/lab.sh scenario oom
    ./scripts/lab.sh scenario pvc-pending

Return to baseline:

    ./scripts/lab.sh scenario healthy

Reset everything:

    ./scripts/lab.sh reset

Destroy the cluster:

    ./scripts/lab.sh down

## Suggested scanner exercises

1. Run `healthy`.
2. Find a `national_id` in customer-service.
3. Search that value across all service logs.
4. Extract `flow_id`.
5. Search `flow_id` across all services.
6. Extract `session_id`.
7. Continue through `attestation_id` and `original_id`.
8. Sort all matching log lines chronologically.
9. Inject one failure.
10. Repeat the correlation and identify where the trace stops.
11. Compare the application failure with Kubernetes symptoms such as:
    - CrashLoopBackOff
    - readiness failures
    - missing endpoints
    - ImagePullBackOff
    - OOMKilled
    - NetworkPolicy denial
    - Pending PVC
12. Record candidate root causes separately from confirmed evidence.

## Important

This lab intentionally performs mutating Kubernetes operations inside the disposable `incident-debug-lab`
cluster when you select a scenario. Your production scanner should remain read-only and must NOT
execute these scenario operations against production.
