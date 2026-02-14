# Kubernetes Manifests for Crypto Application

This directory contains the Kubernetes manifest files for deploying the cryptography application.

## Files Overview

### 00-namespace.yaml
- Creates the `crypto-system` namespace
- Isolates the application from other workloads

### 01-configmap.yaml
- Stores configuration for socket path, mode, and default messages
- Allows easy configuration without rebuilding images

### 02-service.yaml
- **crypto-receiver-service**: ClusterIP service for accessing receiver pods
- **crypto-receiver-headless**: Headless service for inter-pod communication

### 03-deployment-receiver.yaml
- Main deployment for the crypto receiver
- 1 replica by default (configurable)
- Includes:
  - Resource requests and limits
  - Liveness and readiness probes
  - Security context (non-root, read-only filesystem)
  - Volume mounts for socket directory

### 04-serviceaccount.yaml
- ServiceAccount for the application
- RBAC Role and RoleBinding for secure access to configmaps

### 05-job-sender.yaml
- One-time job that sends a message
- **Note**: This manifest is provided for reference but not deployed by default
- For Kubernetes inter-pod communication, consider modifying the application to use network sockets (TCP/gRPC) instead of Unix domain sockets
- To use locally: copy the application to run sender and receiver in the same pod or on the same host

### 06-cronjob-demo.yaml
- Scheduled job running the demo mode every 6 hours
- Useful for periodic cryptography demonstrations

### 07-networkpolicy.yaml
- Network policies for inter-pod communication
- Restricts egress to necessary endpoints (DNS, HTTPS)
- Allows ingress from other crypto-app pods

### 08-poddisruptionbudget.yaml
- Ensures minimum availability during cluster updates
- Prevents all receiver pods from being disrupted simultaneously

## Deployment Instructions

### Prerequisites
1. Kubernetes cluster (1.19+)
2. `kubectl` configured to access the cluster
3. Docker image built and pushed to registry

### Quick Deploy

```bash
# 1. Build and push the image (or use existing)
docker build -t docker.io/yourusername/crypto-app:1.0.0 .

# 2. Update the image in the deployment manifest
sed -i 's|image: crypto-app:latest|image: docker.io/yourusername/crypto-app:1.0.0|g' k8s/03-deployment-receiver.yaml

# 3. Apply all manifests
kubectl apply -f k8s/

# 4. Check deployment status
kubectl get pods -n crypto-system
kubectl logs -n crypto-system -l app=crypto-app -f
```

### Manual Deployment

```bash
# Create namespace
kubectl apply -f k8s/00-namespace.yaml

# Create configuration
kubectl apply -f k8s/01-configmap.yaml

# Create RBAC
kubectl apply -f k8s/04-serviceaccount.yaml

# Create services
kubectl apply -f k8s/02-service.yaml

# Create receiver deployment
kubectl apply -f k8s/03-deployment-receiver.yaml

# Apply policies
kubectl apply -f k8s/07-networkpolicy.yaml
kubectl apply -f k8s/08-poddisruptionbudget.yaml

# Deploy sender job
kubectl apply -f k8s/05-job-sender.yaml

# Deploy demo cronjob (optional)
kubectl apply -f k8s/06-cronjob-demo.yaml
```

## Common Commands

```bash
# Check deployment status
kubectl get all -n crypto-system

# View logs
kubectl logs -n crypto-system deployment/crypto-receiver -f

# Execute command in pod
kubectl exec -it -n crypto-system pod/crypto-receiver-xxx -- /bin/bash

# Delete deployment
kubectl delete -f k8s/

# Manual job execution
kubectl create job manual-sender --from=cronjob/crypto-demo -n crypto-system
kubectl delete job manual-sender -n crypto-system
```

## Configuration

Edit `01-configmap.yaml` to change:
- `SOCKET_PATH`: Socket file location
- `MODE`: receive, send, or demo
- `MESSAGE`: Default message for sender

## Security Notes

1. **Non-root User**: Application runs as UID 1000
2. **Read-only Filesystem**: Root filesystem is mounted read-only
3. **No Capabilities**: All Linux capabilities are dropped
4. **Network Policies**: Restrict pod-to-pod and pod-to-external communication
5. **RBAC**: Minimal permissions assigned via ServiceAccount and Role

## Troubleshooting

### Pod not starting
```bash
kubectl describe pod -n crypto-system <pod-name>
kubectl logs -n crypto-system <pod-name>
```

### Cannot pull image
```bash
# Check image registry credentials
kubectl get secrets -n crypto-system
# Or create docker registry secret
kubectl create secret docker-registry regcred \
  --docker-server=docker.io \
  --docker-username=<username> \
  --docker-password=<password> \
  -n crypto-system
```

### Mount permission issues
```bash
# Check volume mounts and permissions
kubectl describe pvc -n crypto-system
kubectl exec -n crypto-system <pod-name> -- ls -la /tmp/sockets
```

## Advanced Customization

### Increase replicas
```bash
kubectl scale deployment crypto-receiver --replicas=3 -n crypto-system
```

### Update image
```bash
kubectl set image deployment/crypto-receiver \
  crypto-receiver=docker.io/yourusername/crypto-app:1.0.1 \
  -n crypto-system
```

### Manual job trigger
```bash
kubectl wait --for=condition=complete job/crypto-sender -n crypto-system
```
