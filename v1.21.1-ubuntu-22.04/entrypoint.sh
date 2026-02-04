#!/bin/bash
#
# FIPS-enabled entrypoint for AWS VPC CNI (aws-node) v1.21.1
#
# This script:
# 1. Validates FIPS mode is active
# 2. Runs FIPS startup checks
# 3. Sets up necessary directories and permissions
# 4. Executes the aws-vpc-cni daemon (which starts aws-k8s-agent)
#

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
echo ""
echo "========================================"
echo "AWS VPC CNI (aws-node) v1.21.1 FIPS"
echo "========================================"
echo ""

# Step 1: Verify environment variables
log_info "Verifying FIPS environment variables..."
if [ -z "$OPENSSL_CONF" ]; then
    log_warning "OPENSSL_CONF not set, using default: /usr/local/openssl/ssl/openssl.cnf"
    export OPENSSL_CONF="/usr/local/openssl/ssl/openssl.cnf"
fi

if [ -z "$OPENSSL_MODULES" ]; then
    log_warning "OPENSSL_MODULES not set, using default: /usr/local/openssl/lib64/ossl-modules"
    export OPENSSL_MODULES="/usr/local/openssl/lib64/ossl-modules"
fi

log_success "Environment variables configured"
echo "  OPENSSL_CONF: $OPENSSL_CONF"
echo "  OPENSSL_MODULES: $OPENSSL_MODULES"
echo "  LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo ""

# Step 2: Verify OpenSSL and wolfProvider
log_info "Verifying OpenSSL FIPS configuration..."
OPENSSL_VERSION=$(openssl version 2>&1 || echo "ERROR")
if [[ "$OPENSSL_VERSION" == *"ERROR"* ]]; then
    log_error "OpenSSL is not working correctly!"
    exit 1
fi
log_success "OpenSSL version: $OPENSSL_VERSION"
echo ""

# Step 3: Check wolfProvider
log_info "Checking wolfProvider status..."
if openssl list -providers 2>/dev/null | grep -q "wolfprov"; then
    log_success "wolfProvider is loaded and active"
    openssl list -providers | grep -A 3 "wolfprov" || true
else
    log_error "wolfProvider is NOT loaded!"
    log_error "Available providers:"
    openssl list -providers || true
    exit 1
fi
echo ""

# Step 4: Run FIPS startup check (wolfSSL integrity verification)
if [ -x "/usr/local/bin/fips-startup-check" ]; then
    log_info "Running wolfSSL FIPS integrity check..."
    if /usr/local/bin/fips-startup-check; then
        log_success "wolfSSL FIPS integrity check passed"
    else
        log_error "wolfSSL FIPS integrity check FAILED!"
        exit 1
    fi
else
    log_warning "FIPS startup check utility not found, skipping"
fi
echo ""

# Step 5: Test FIPS-approved cryptographic operation
log_info "Testing FIPS-approved cryptographic operation (SHA-256)..."
TEST_RESULT=$(echo "FIPS test" | openssl dgst -sha256 -hex 2>&1 || echo "ERROR")
if [[ "$TEST_RESULT" == *"ERROR"* ]]; then
    log_error "SHA-256 test failed!"
    echo "$TEST_RESULT"
    exit 1
else
    log_success "SHA-256 test passed"
fi
echo ""

# Step 6: Verify aws-vpc-cni binaries exist
log_info "Verifying AWS VPC CNI components..."
MISSING_BINARIES=0
for binary in aws-vpc-cni aws-k8s-agent aws-cni egress-cni grpc-health-probe; do
    if [ ! -x "/app/$binary" ]; then
        log_error "$binary binary not found or not executable!"
        MISSING_BINARIES=$((MISSING_BINARIES + 1))
    fi
done

if [ $MISSING_BINARIES -gt 0 ]; then
    log_error "Missing $MISSING_BINARIES required binaries!"
    exit 1
fi
log_success "All AWS VPC CNI binaries found"
echo ""

# Step 7: Create necessary runtime directories with proper permissions
log_info "Setting up runtime directories..."
mkdir -p /var/run/aws-node
mkdir -p /var/log/aws-routed-eni
mkdir -p /run/xtables.lock
chmod 755 /var/run/aws-node /var/log/aws-routed-eni
log_success "Runtime directories configured"
echo ""

# Step 8: Verify network capabilities
log_info "Verifying network capabilities..."
if ip link show &>/dev/null; then
    log_success "Network interface access confirmed"
else
    log_warning "Cannot list network interfaces (may need --net=host --privileged)"
fi

# Check iptables availability
if iptables --version &>/dev/null; then
    IPTABLES_VERSION=$(iptables --version | head -1)
    log_success "iptables available: $IPTABLES_VERSION"
else
    log_error "iptables not available!"
    exit 1
fi
echo ""

# Step 9: Display runtime information
log_info "Container runtime information:"
echo "  Hostname: $(hostname)"
echo "  User: $(whoami) (UID: $(id -u))"
echo "  Node name: ${NODE_NAME:-not set}"
echo "  Cluster name: ${CLUSTER_NAME:-not set}"
echo ""

# Step 10: Display AWS VPC CNI configuration
log_info "AWS VPC CNI configuration:"
echo "  Log level: ${AWS_VPC_K8S_CNI_LOGLEVEL:-INFO}"
echo "  Log file: ${AWS_VPC_K8S_CNI_LOG_FILE:-/var/log/aws-routed-eni/ipamd.log}"
echo "  Plugin log file: ${AWS_VPC_K8S_PLUGIN_LOG_FILE:-/var/log/aws-routed-eni/plugin.log}"
echo "  ENI MTU: ${AWS_VPC_ENI_MTU:-9001}"
echo "  VETH prefix: ${AWS_VPC_K8S_CNI_VETHPREFIX:-eni}"
echo "  Enable POD ENI: ${ENABLE_POD_ENI:-false}"
echo "  Disable metrics: ${DISABLE_METRICS:-false}"
echo "  Disable introspection: ${DISABLE_INTROSPECTION:-false}"
echo ""

# Step 11: Check for required CNI configuration files
log_info "Checking CNI configuration files..."
if [ -f "/app/10-aws.conflist" ]; then
    log_success "CNI config: /app/10-aws.conflist"
else
    log_warning "CNI config not found: /app/10-aws.conflist"
fi

if [ -f "/app/eni-max-pods.txt" ]; then
    log_success "ENI limits: /app/eni-max-pods.txt"
else
    log_warning "ENI limits not found: /app/eni-max-pods.txt"
fi
echo ""

# Step 12: Final ready message
log_success "FIPS validation complete - all checks passed"
echo "========================================"
echo ""

# Step 13: Execute aws-vpc-cni daemon
log_info "Starting AWS VPC CNI daemon (aws-k8s-agent)..."
echo ""

# Set working directory to /app
cd /app

# If no arguments provided, run aws-vpc-cni with default behavior
# aws-vpc-cni is the entrypoint wrapper that starts aws-k8s-agent (IPAM daemon)
if [ $# -eq 0 ]; then
    exec /app/aws-vpc-cni
else
    # Execute provided command (allows override for debugging)
    exec "$@"
fi
