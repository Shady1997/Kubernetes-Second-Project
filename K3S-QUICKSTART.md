# K3s Quick Start

This version is K3s-native. Do not install kind.

```bash
chmod +x scripts/*.sh
./scripts/lab.sh up
```

The script builds `incident-lab:v5`, imports it with `k3s ctr`, and deploys only the `trace-lab` namespace.

Verify:

```bash
kubectl -n trace-lab get pods -o wide
kubectl -n trace-lab get svc,endpoints
kubectl -n trace-lab logs -l app=customer-service --tail=20
```

Trace IDs:

```text
national_id -> flow_id -> session_id -> attestation_id -> original_id
```

Run an incident:

```bash
./scripts/lab.sh scenario attestation-500
kubectl -n trace-lab get pods
kubectl -n trace-lab get events --sort-by=.lastTimestamp
```

Reset:

```bash
./scripts/lab.sh reset
```

Remove only the lab namespace:

```bash
./scripts/lab.sh down
```
