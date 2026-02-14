#!/bin/bash

# Kubernetes Deployment Script for Crypto Applications
# Automates building, pushing, and deploying to Kubernetes

set -e  # Exit on error

set -a
source .env
set +a

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="${NAMESPACE:-crypto-system}"
IMAGE_NAME="${IMAGE_NAME:-crypto-app}"
IMAGE_VERSION="${IMAGE_VERSION:-1.0.0}"
REGISTRY="${REGISTRY:-docker.io/yourusername}"
K8S_DIR="${K8S_DIR:-k8s}"

# Print colored output
print_info() { echo -e "${BLUE}ℹ $1${NC}"; }
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo ""
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    local missing_tools=()
    
    if ! command_exists kubectl; then
        missing_tools+=("kubectl")
    fi
    
    if ! command_exists docker; then
        missing_tools+=("docker")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        echo ""
        echo "Install instructions:"
        echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    print_success "kubectl found: $(kubectl version --client --short 2>/dev/null | head -n1)"
    print_success "docker found: $(docker --version)"
    
    # Check kubectl access
    if kubectl cluster-info >/dev/null 2>&1; then
        print_success "kubectl can access cluster"
        print_info "Cluster: $(kubectl config current-context)"
    else
        print_error "kubectl cannot access cluster"
        exit 1
    fi
}

# Build Docker image
build_image() {
    print_header "Building Docker Image"
    
    print_info "Building ${IMAGE_NAME}:${IMAGE_VERSION}..."
    
    if docker build -t "${IMAGE_NAME}:${IMAGE_VERSION}" .; then
        print_success "Image built successfully"
    else
        print_error "Image build failed"
        exit 1
    fi
    
    # Tag with latest
    docker tag "${IMAGE_NAME}:${IMAGE_VERSION}" "${IMAGE_NAME}:latest"
    print_success "Tagged as ${IMAGE_NAME}:latest"
}

# Push Docker image
push_image() {
    print_header "Pushing Docker Image"
    
    local full_image="${REGISTRY}/${IMAGE_NAME}:${IMAGE_VERSION}"
    local full_image_latest="${REGISTRY}/${IMAGE_NAME}:latest"
    
    print_info "Tagging for registry..."
    docker tag "${IMAGE_NAME}:${IMAGE_VERSION}" "${full_image}"
    docker tag "${IMAGE_NAME}:${IMAGE_VERSION}" "${full_image_latest}"
    print_success "Tagged as ${full_image}"
    
    print_info "Pushing to registry..."
    if docker push "${full_image}" && docker push "${full_image_latest}"; then
        print_success "Images pushed successfully"
    else
        print_error "Image push failed"
        print_warning "Make sure you're logged in: docker login ${REGISTRY}"
        exit 1
    fi
}

# Update Kubernetes manifests
update_manifests() {
    print_header "Updating Kubernetes Manifests"
    
    local full_image="${REGISTRY}/${IMAGE_NAME}:${IMAGE_VERSION}"
    
    print_info "Updating image references in manifests..."
    
    # Update receiver deployment
    if [ -f "${K8S_DIR}/03-deployment-receiver.yaml" ]; then
        sed -i.bak "s|image: crypto-app:.*|image: ${full_image}|g" \
            "${K8S_DIR}/03-deployment-receiver.yaml"
        print_success "Updated receiver deployment"
    fi
    
    # Update sender job
    if [ -f "${K8S_DIR}/05-job-sender.yaml" ]; then
        sed -i.bak "s|image: crypto-app:.*|image: ${full_image}|g" \
            "${K8S_DIR}/05-job-sender.yaml"
        print_success "Updated sender job"
    fi
    
    # Remove backup files
    find "${K8S_DIR}" -name "*.bak" -delete
}

# Deploy to Kubernetes
deploy_k8s() {
    print_header "Deploying to Kubernetes"
    
    # Create namespace if it doesn't exist
    if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
        print_info "Creating namespace ${NAMESPACE}..."
        kubectl apply -f "${K8S_DIR}/00-namespace.yaml"
        print_success "Namespace created"
    else
        print_info "Namespace ${NAMESPACE} already exists"
    fi
    
    # Apply all manifests
    print_info "Applying Kubernetes manifests..."
    if kubectl apply -f "${K8S_DIR}/"; then
        print_success "Manifests applied successfully"
    else
        print_error "Failed to apply manifests"
        exit 1
    fi
    
    # Wait for receiver deployment
    print_info "Waiting for receiver deployment to be ready..."
    if kubectl rollout status deployment/crypto-receiver -n "${NAMESPACE}" --timeout=2m; then
        print_success "Receiver deployment is ready"
    else
        print_warning "Receiver deployment not ready yet"
    fi
}

# Check deployment status
check_status() {
    print_header "Deployment Status"
    
    echo "Namespace: ${NAMESPACE}"
    echo ""
    
    print_info "Deployments:"
    kubectl get deployments -n "${NAMESPACE}"
    echo ""
    
    print_info "Pods:"
    kubectl get pods -n "${NAMESPACE}"
    echo ""
    
    print_info "Services:"
    kubectl get services -n "${NAMESPACE}"
    echo ""
    
    print_info "Jobs:"
    kubectl get jobs -n "${NAMESPACE}"
    echo ""
    
    print_info "PVCs:"
    kubectl get pvc -n "${NAMESPACE}"
    echo ""
}

# View logs
view_logs() {
    local component="${1:-receiver}"
    
    print_header "Viewing Logs: ${component}"
    
    if [ "${component}" == "receiver" ]; then
        kubectl logs -n "${NAMESPACE}" -l app=crypto-app,component=receiver --tail=50 -f
    elif [ "${component}" == "sender" ]; then
        kubectl logs -n "${NAMESPACE}" -l app=crypto-app,component=sender --tail=50
    else
        print_error "Unknown component: ${component}"
        echo "Valid components: receiver, sender"
        exit 1
    fi
}

# Run sender locally (not in Kubernetes)
run_sender() {
    local message="${1:-Test message from deployment script}"
    
    print_header "Running Secure Sender"
    
    # Check if receiver pod is ready
    print_info "Checking receiver status in Kubernetes..."
    if ! kubectl get pods -n "${NAMESPACE}" -l app=crypto-app,component=receiver | grep -q "Running"; then
        print_error "Receiver pod is not running"
        echo "Make sure to deploy first: $0 deploy"
        exit 1
    fi
    print_success "Receiver pod is running"
    
    echo ""
    
    # Get the receiver pod name
    local receiver_pod=$(kubectl get pods -n "${NAMESPACE}" -l app=crypto-app,component=receiver --no-headers -o custom-columns=NAME:.metadata.name | head -1)
    
    if [ -z "$receiver_pod" ]; then
        print_error "Could not find receiver pod"
        exit 1
    fi
    
    print_info "Using receiver pod: $receiver_pod"
    print_info "Running sender inside pod (shares the socket)..."
    echo ""
    
    # Run the sender inside the receiver pod
    kubectl exec -it -n "${NAMESPACE}" "$receiver_pod" -- /app/secure_transfer send "${message}"
    
    echo ""
    echo "Checking receiver pod logs:"
    echo "---"
    kubectl logs -n "${NAMESPACE}" "$receiver_pod" --tail=30
}

# Clean up deployment
cleanup() {
    print_header "Cleaning Up Deployment"
    
    print_warning "This will delete the entire ${NAMESPACE} namespace and all resources"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        print_info "Cleanup cancelled"
        exit 0
    fi
    
    print_info "Deleting namespace ${NAMESPACE}..."
    if kubectl delete namespace "${NAMESPACE}"; then
        print_success "Namespace deleted"
    else
        print_error "Failed to delete namespace"
        exit 1
    fi
    
    print_info "Cleaning up local Docker images..."
    docker rmi "${IMAGE_NAME}:${IMAGE_VERSION}" 2>/dev/null || true
    docker rmi "${IMAGE_NAME}:latest" 2>/dev/null || true
    print_success "Cleanup complete"
}

# Show usage
usage() {
    cat << EOF
Kubernetes Deployment Script for Crypto Applications

Usage: $0 <command> [options]

Commands:
    build           Build Docker image
    push            Push image to registry
    deploy          Deploy to Kubernetes (includes build and push)
    status          Check deployment status
    logs [component]  View logs (receiver or sender)
    send [message]  Run sender job with optional message
    cleanup         Delete all resources
    help            Show this help message

Examples:
    $0 deploy                          # Build, push, and deploy
    $0 status                          # Check status
    $0 logs receiver                   # View receiver logs
    $0 send "Hello from K8s"          # Send a message
    $0 cleanup                         # Clean up everything

Environment Variables:
    NAMESPACE       Kubernetes namespace (default: crypto-system)
    IMAGE_NAME      Docker image name (default: crypto-app)
    IMAGE_VERSION   Image version tag (default: 1.0.0)
    REGISTRY        Docker registry (default: docker.io/yourusername)
    K8S_DIR         Kubernetes manifests directory (default: k8s)

Configuration:
    Before deploying, update the REGISTRY variable in this script
    or set it as an environment variable:
        export REGISTRY=your-registry.example.com/yourname

EOF
}

# Main script
main() {
    local command="${1:-help}"
    
    case "$command" in
        build)
            check_prerequisites
            build_image
            ;;
        
        push)
            check_prerequisites
            push_image
            ;;
        
        deploy)
            check_prerequisites
            build_image
            push_image
            update_manifests
            deploy_k8s
            check_status
            print_success "Deployment complete!"
            echo ""
            print_info "Next steps:"
            echo "  View status: $0 status"
            echo "  View logs: $0 logs receiver"
            echo "  Send message: $0 send 'Your message'"
            ;;
        
        status)
            check_prerequisites
            check_status
            ;;
        
        logs)
            check_prerequisites
            view_logs "${2:-receiver}"
            ;;
        
        send)
            check_prerequisites
            run_sender "${2:-Test message}"
            ;;
        
        cleanup)
            check_prerequisites
            cleanup
            ;;
        
        help|--help|-h)
            usage
            ;;
        
        *)
            print_error "Unknown command: $command"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"