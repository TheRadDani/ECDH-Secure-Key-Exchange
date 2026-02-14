# Docker & Kubernetes Quick Start Guide

Complete guide for containerizing and deploying the cryptography applications.

## Table of Contents

1. [Docker Deployment](#docker-deployment)
2. [Docker Compose](#docker-compose)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Helm Deployment](#helm-deployment)
5. [Production Considerations](#production-considerations)

---

## Docker Deployment

### Build the Image

```bash
# Build production image
docker build -t crypto-app:1.0.0 .

# Build with build args
docker build \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t crypto-app:1.0.0 .

# Build debug image
docker build --target debug -t crypto-app:debug .
```

### Run Containers

```bash
# Create shared volume
docker volume create socket-data

# Run receiver
docker run -d \
  --name crypto-receiver \
  -e MODE=receive \
  -v socket-data:/tmp/sockets \
  crypto-app:1.0.0

# Wait for receiver to start
sleep 3

# Run sender
docker run --rm \
  --name crypto-sender \
  -e MODE=send \
  -e MESSAGE="Hello from Docker!" \
  -v socket-data:/tmp/sockets \
  crypto-app:1.0.0

# View logs
docker logs crypto-receiver
docker logs crypto-sender

# Clean up
docker stop crypto-receiver
docker rm crypto-receiver
docker volume rm socket-data
```

### Push to Registry

```bash
# Login to Docker Hub
docker login

# Tag for registry
docker tag crypto-app:1.0.0 yourusername/crypto-app:1.0.0
docker tag crypto-app:1.0.0 yourusername/crypto-app:latest

# Push
docker push yourusername/crypto-app:1.0.0
docker push yourusername/crypto-app:latest
```

---

## Docker Compose

### Quick Start

```bash
# Start both receiver and sender
docker-compose up

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Run only demo
docker-compose --profile demo up demo

# Stop all
docker-compose down

# Clean up volumes
docker-compose down -v
```

### Custom Configuration

Create `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  receiver:
    environment:
      LOG_LEVEL: debug
    
  sender:
    environment:
      MESSAGE: "Custom message from override"
```

Run with override:
```bash
docker-compose up
```

---

## ☸️ Kubernetes Deployment

### Method 1: Automated Script (Recommended)

```bash
# Make script executable
chmod +x deploy-k8s.sh

# Configure registry (IMPORTANT!)
export REGISTRY="your-registry.example.com/yourusername"

# Deploy everything
./deploy-k8s.sh deploy

# Check status
./deploy-k8s.sh status

# View logs
./deploy-k8s.sh logs receiver

# Send message
./deploy-k8s.sh send "Hello from K8s!"

# Clean up
./deploy-k8s.sh cleanup
```

### Method 2: Manual Deployment

```bash
# Set your registry
REGISTRY="your-registry.example.com/yourusername"

# 1. Build and push
docker build -t crypto-app:1.0.0 .
docker tag crypto-app:1.0.0 ${REGISTRY}/crypto-app:1.0.0
docker push ${REGISTRY}/crypto-app:1.0.0

# 2. Update manifests
sed -i "s|crypto-app:1.0.0|${REGISTRY}/crypto-app:1.0.0|g" \
  k8s/03-deployment-receiver.yaml \
  k8s/05-job-sender.yaml

# 3. Deploy
kubectl apply -f k8s/

# 4. Verify
kubectl get all -n crypto-system

# 5. View logs
kubectl logs -n crypto-system -l app=crypto-receiver

# 6. Clean up
kubectl delete namespace crypto-system
```

### Method 3: Kustomize

```bash
# Create kustomization
cat <<EOF > k8s/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: crypto-system

resources:
  - 00-namespace.yaml
  - 01-configmap.yaml
  - 02-pvc.yaml
  - 03-deployment-receiver.yaml
  - 04-service-receiver.yaml
  - 05-job-sender.yaml
  - 06-networkpolicy.yaml
  - 07-resource-limits.yaml
  - 08-autoscaling.yaml

images:
  - name: crypto-app
    newName: your-registry/crypto-app
    newTag: 1.0.0

commonLabels:
  environment: production
  managed-by: kustomize
EOF

# Deploy
kubectl apply -k k8s/

# Delete
kubectl delete -k k8s/
```

---

## ⎈ Helm Deployment

### Install Helm Chart

```bash
# Install with default values
helm install my-crypto ./helm/crypto-transfer

# Install with custom values
helm install my-crypto ./helm/crypto-transfer \
  --set image.repository=your-registry/crypto-app \
  --set image.tag=1.0.0 \
  --set receiver.replicaCount=3

# Install with values file
cat <<EOF > my-values.yaml
image:
  repository: your-registry/crypto-app
  tag: 1.0.0

receiver:
  replicaCount: 3
  resources:
    requests:
      memory: 128Mi
      cpu: 100m

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
EOF

helm install my-crypto ./helm/crypto-transfer -f my-values.yaml

# Install in specific namespace
helm install my-crypto ./helm/crypto-transfer \
  --namespace crypto-prod \
  --create-namespace
```

### Manage Helm Release

```bash
# List releases
helm list

# Get status
helm status my-crypto

# Get values
helm get values my-crypto

# Upgrade
helm upgrade my-crypto ./helm/crypto-transfer \
  --set image.tag=1.1.0

# Rollback
helm rollback my-crypto

# Uninstall
helm uninstall my-crypto
```

### Test Helm Chart

```bash
# Lint
helm lint ./helm/crypto-transfer

# Dry run
helm install my-crypto ./helm/crypto-transfer --dry-run --debug

# Template
helm template my-crypto ./helm/crypto-transfer

# Package
helm package ./helm/crypto-transfer
```

---

## 🏭 Production Considerations

### Security Checklist

- [ ] Use specific image tags, not `latest`
- [ ] Scan images for vulnerabilities
- [ ] Use private registry with authentication
- [ ] Enable network policies
- [ ] Set resource limits
- [ ] Run as non-root user
- [ ] Use read-only root filesystem
- [ ] Drop all capabilities
- [ ] Enable Pod Security Standards
- [ ] Use secrets for sensitive data
- [ ] Enable RBAC with minimal permissions
- [ ] Use TLS for all communications

### Performance Optimization

```yaml
# Example optimized configuration
receiver:
  replicaCount: 3
  
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 512Mi
  
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: app
              operator: In
              values:
              - crypto-receiver
          topologyKey: kubernetes.io/hostname

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 70
```

### High Availability

```yaml
# Multi-zone deployment
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app
          operator: In
          values:
          - crypto-receiver
      topologyKey: topology.kubernetes.io/zone

# Pod disruption budget
podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

### Monitoring Setup

```yaml
# Enable Prometheus monitoring
monitoring:
  enabled: true
  prometheus:
    enabled: true
    port: 9090
  
  serviceMonitor:
    enabled: true
    interval: 30s
    scrapeTimeout: 10s
```

### Logging Configuration

```bash
# Centralized logging with Fluentd
kubectl apply -f https://raw.githubusercontent.com/fluent/fluentd-kubernetes-daemonset/master/fluentd-daemonset-elasticsearch.yaml

# Configure log aggregation
helm install my-crypto ./helm/crypto-transfer \
  --set logging.enabled=true \
  --set logging.level=info
```

### Backup Strategy

```bash
# Backup namespace
kubectl get all -n crypto-system -o yaml > backup-crypto-system.yaml

# Backup PVCs
kubectl get pvc -n crypto-system -o yaml > backup-pvcs.yaml

# Use Velero for automated backups
velero backup create crypto-backup \
  --include-namespaces crypto-system \
  --storage-location default
```

---

## Comparison Matrix

| Feature | Docker | Docker Compose | Kubernetes | Helm |
|---------|--------|----------------|------------|------|
| **Complexity** | Low | Low | High | Medium |
| **Learning Curve** | Easy | Easy | Steep | Moderate |
| **Scalability** | Manual | Manual | Automatic | Automatic |
| **Production Ready** | No | Limited | Yes | Yes |
| **Best For** | Development | Local Testing | Production | Production |
| **HA Support** | No | No | Yes | Yes |
| **Auto-healing** | No | Restart only | Yes | Yes |
| **Configuration Management** | Limited | Good | Excellent | Excellent |

---

## Quick Decision Guide

**Use Docker directly if:**
- Testing locally
- Simple single-container deployment
- Learning containerization

**Use Docker Compose if:**
- Local development
- Simple multi-container apps
- Quick prototyping

**Use Kubernetes if:**
- Production deployment
- Need auto-scaling
- High availability required
- Complex orchestration

**Use Helm if:**
- Managing multiple K8s deployments
- Need configuration templates
- Want easy upgrades/rollbacks
- Production best practices

---

## Common Issues

### Image Pull Errors

```bash
# Create registry secret
kubectl create secret docker-registry regcred \
  -n crypto-system \
  --docker-server=your-registry \
  --docker-username=username \
  --docker-password=password

# Reference in deployment
imagePullSecrets:
  - name: regcred
```

### Resource Constraints

```bash
# Check node resources
kubectl top nodes

# Adjust limits
helm upgrade my-crypto ./helm/crypto-transfer \
  --set receiver.resources.limits.memory=512Mi
```

### Storage Issues

```bash
# Check storage classes
kubectl get storageclass

# Use specific class
helm install my-crypto ./helm/crypto-transfer \
  --set persistence.storageClass=fast-ssd
```

---