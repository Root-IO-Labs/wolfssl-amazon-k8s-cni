#!/bin/bash
#
# Cluster Test Suite for AWS VPC CNI FIPS Deployment
# Tests the deployed aws-node DaemonSet in a live Kubernetes cluster
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="kube-system"
POD_LABEL="k8s-app=aws-node"
CONTAINER_NAME="aws-node"
KUBECTL="/usr/local/bin/kubectl"

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TEST_RESULTS=()

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓ PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TEST_RESULTS+=("PASS: $1")
}

log_fail() {
    echo -e "${RED}[✗ FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TEST_RESULTS+=("FAIL: $1")
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Get pod name
get_pod_name() {
    $KUBECTL get pod -n "$NAMESPACE" -l "$POD_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo ""
}

# Test functions
test_pod_exists() {
    log_info "Test 1: Checking if aws-node pod exists..."
    POD_NAME=$(get_pod_name)
    if [ -n "$POD_NAME" ]; then
        log_success "aws-node pod found: $POD_NAME"
        echo "$POD_NAME"
        return 0
    else
        log_fail "aws-node pod not found"
        return 1
    fi
}

test_pod_ready() {
    log_info "Test 2: Checking if aws-node pod is ready..."
    local pod_name=$1
    local ready_status=$($KUBECTL get pod -n "$NAMESPACE" "$pod_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
    if [ "$ready_status" = "True" ]; then
        log_success "aws-node pod is ready"
        return 0
    else
        log_fail "aws-node pod is not ready (status: $ready_status)"
        return 1
    fi
}

test_correct_image() {
    log_info "Test 3: Verifying correct FIPS image is deployed..."
    local pod_name=$1
    local image=$($KUBECTL get pod -n "$NAMESPACE" "$pod_name" -o jsonpath='{.spec.containers[0].image}')
    if [[ "$image" == *"rootioinc/amazon-k8s-cni"*"fips"* ]]; then
        log_success "Correct FIPS image deployed: $image"
        return 0
    else
        log_fail "Incorrect image deployed: $image"
        return 1
    fi
}

test_fips_provider_loaded() {
    log_info "Test 4: Verifying FIPS wolfProvider is loaded..."
    local pod_name=$1
    local output=$($KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- openssl list -providers 2>&1)
    if echo "$output" | grep -q "wolfprov"; then
        log_success "wolfProvider is loaded and active"
        return 0
    else
        log_fail "wolfProvider is not loaded"
        return 1
    fi
}

test_fips_startup_check() {
    log_info "Test 5: Running FIPS startup validation..."
    local pod_name=$1
    local output=$($KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- /usr/local/bin/fips-startup-check 2>&1)
    if echo "$output" | grep -q "FIPS VALIDATION PASSED"; then
        log_success "FIPS startup validation passed"
        return 0
    else
        log_fail "FIPS startup validation failed"
        return 1
    fi
}

test_openssl_version() {
    log_info "Test 6: Checking OpenSSL version..."
    local pod_name=$1
    local version=$($KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- openssl version 2>&1)
    if [[ "$version" == *"OpenSSL 3"* ]]; then
        log_success "OpenSSL 3.x detected: $version"
        return 0
    else
        log_warn "Unexpected OpenSSL version: $version"
        return 1
    fi
}

test_no_non_fips_libs() {
    log_info "Test 7: Checking for non-FIPS crypto libraries..."
    local pod_name=$1
    local found_libs=$($KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- find /usr/lib /lib -name 'libgnutls*' -o -name 'libnettle*' -o -name 'libhogweed*' 2>/dev/null | wc -l || echo "0")
    if [ "$found_libs" -eq 0 ]; then
        log_success "No non-FIPS crypto libraries found"
        return 0
    else
        log_fail "Found $found_libs non-FIPS crypto library files"
        return 1
    fi
}

test_aws_node_binary() {
    log_info "Test 8: Verifying aws-k8s-agent binary exists..."
    local pod_name=$1
    if $KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- test -x /app/aws-k8s-agent 2>/dev/null; then
        log_success "aws-k8s-agent binary found and executable"
        return 0
    else
        log_fail "aws-k8s-agent binary not found or not executable"
        return 1
    fi
}

test_cni_plugin_binary() {
    log_info "Test 9: Verifying aws-cni plugin binary exists..."
    local pod_name=$1
    if $KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- test -x /app/aws-cni 2>/dev/null; then
        log_success "aws-cni plugin binary found and executable"
        return 0
    else
        log_fail "aws-cni plugin binary not found or not executable"
        return 1
    fi
}

test_container_restarts() {
    log_info "Test 10: Checking for container restarts..."
    local pod_name=$1
    local restarts=$($KUBECTL get pod -n "$NAMESPACE" "$pod_name" -o jsonpath='{.status.containerStatuses[0].restartCount}')
    if [ "$restarts" -lt 3 ]; then
        log_success "Container restart count is acceptable: $restarts"
        return 0
    else
        log_warn "Container has restarted $restarts times"
        return 1
    fi
}

test_pod_networking() {
    log_info "Test 11: Testing pod network connectivity..."
    local pod_name=$1
    if $KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- curl -s --max-time 5 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
        log_success "Pod has network connectivity to EC2 metadata service"
        return 0
    else
        log_warn "Cannot reach EC2 metadata service (may be expected in some environments)"
        return 0  # Don't fail for this
    fi
}

test_metrics_endpoint() {
    log_info "Test 12: Checking metrics endpoint availability..."
    local pod_name=$1
    if $KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- curl -s http://localhost:61678/metrics >/dev/null 2>&1; then
        log_success "Metrics endpoint is accessible"
        return 0
    else
        log_warn "Metrics endpoint is not accessible"
        return 1
    fi
}

test_log_files() {
    log_info "Test 13: Checking if log files are being created..."
    local pod_name=$1
    # Check if log directory exists
    if $KUBECTL exec -n "$NAMESPACE" "$pod_name" -c "$CONTAINER_NAME" -- test -d /var/log/aws-routed-eni 2>/dev/null; then
        log_success "Log directory exists"
        return 0
    else
        log_warn "Log directory not found"
        return 1
    fi
}

test_daemonset_status() {
    log_info "Test 14: Checking DaemonSet status..."
    local desired=$($KUBECTL get daemonset -n "$NAMESPACE" aws-node -o jsonpath='{.status.desiredNumberScheduled}')
    local ready=$($KUBECTL get daemonset -n "$NAMESPACE" aws-node -o jsonpath='{.status.numberReady}')
    if [ "$desired" -eq "$ready" ]; then
        log_success "DaemonSet is fully deployed: $ready/$desired pods ready"
        return 0
    else
        log_fail "DaemonSet not fully deployed: $ready/$desired pods ready"
        return 1
    fi
}

test_rbac_permissions() {
    log_info "Test 15: Checking RBAC permissions..."
    if $KUBECTL get clusterrole aws-node >/dev/null 2>&1 && \
       $KUBECTL get clusterrolebinding aws-node >/dev/null 2>&1 && \
       $KUBECTL get serviceaccount -n "$NAMESPACE" aws-node >/dev/null 2>&1; then
        log_success "RBAC resources (ClusterRole, ClusterRoleBinding, ServiceAccount) exist"
        return 0
    else
        log_fail "Missing RBAC resources"
        return 1
    fi
}

# Main test execution
main() {
    echo "========================================"
    echo "AWS VPC CNI FIPS - Cluster Test Suite"
    echo "========================================"
    echo ""
    echo "Test Execution: $(date)"
    echo "Namespace: $NAMESPACE"
    echo "Pod Label: $POD_LABEL"
    echo ""
    echo "========================================"
    echo ""

    # Run all tests
    POD_NAME=""

    # Test 1: Pod exists
    if test_pod_exists; then
        POD_NAME=$(get_pod_name)
        echo ""

        # Tests requiring pod name
        test_pod_ready "$POD_NAME" || true
        echo ""
        test_correct_image "$POD_NAME" || true
        echo ""
        test_fips_provider_loaded "$POD_NAME" || true
        echo ""
        test_fips_startup_check "$POD_NAME" || true
        echo ""
        test_openssl_version "$POD_NAME" || true
        echo ""
        test_no_non_fips_libs "$POD_NAME" || true
        echo ""
        test_aws_node_binary "$POD_NAME" || true
        echo ""
        test_cni_plugin_binary "$POD_NAME" || true
        echo ""
        test_container_restarts "$POD_NAME" || true
        echo ""
        test_pod_networking "$POD_NAME" || true
        echo ""
        test_metrics_endpoint "$POD_NAME" || true
        echo ""
        test_log_files "$POD_NAME" || true
        echo ""
    fi

    # Tests not requiring specific pod
    test_daemonset_status || true
    echo ""
    test_rbac_permissions || true
    echo ""

    # Summary
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo ""
    echo "Total Tests Passed: $TESTS_PASSED"
    echo "Total Tests Failed: $TESTS_FAILED"
    echo "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
        echo ""
        echo "========================================"
        exit 0
    else
        echo -e "${YELLOW}⚠ SOME TESTS FAILED${NC}"
        echo ""
        echo "Failed tests:"
        for result in "${TEST_RESULTS[@]}"; do
            if [[ "$result" == FAIL:* ]]; then
                echo "  - ${result#FAIL: }"
            fi
        done
        echo ""
        echo "========================================"
        exit 1
    fi
}

# Run tests
main "$@"
