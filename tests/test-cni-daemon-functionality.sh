#!/bin/bash
################################################################################
# AWS VPC CNI (aws-node) v1.21.1 - Daemon Functionality Tests
#
# Purpose: Test daemon-specific functionality including:
#          - Entrypoint FIPS validation
#          - Binary execution
#          - Network tools availability
#          - Configuration file handling
#          - Volume mount expectations
#          - Health probe functionality
#
# Usage:
#   ./tests/test-cni-daemon-functionality.sh [image-name]
#
# Example:
#   ./tests/test-cni-daemon-functionality.sh amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04
#
# Test Coverage:
#   • Entrypoint Validation (6 checks)
#   • Binary Execution Tests (5 checks)
#   • Network Tools Verification (7 checks)
#   • Configuration File Tests (4 checks)
#   • Volume Mount Requirements (4 checks)
#   • Health Probe Functionality (3 checks)
#
# Total Checks: 29
# Expected Duration: ~60 seconds
#
# Exit Codes:
#   0 - All functionality tests passed
#   1 - One or more tests failed
#
# Last Updated: 2026-01-13
# Version: 1.0
################################################################################

set -e

################################################################################
# Configuration
################################################################################

IMAGE_NAME="${1:-amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo ""
    echo "Test $TOTAL_TESTS: $test_name"
    echo "----------------------------------------"

    if output=$(eval "$test_command" 2>&1); then
        if echo "$output" | grep -qE "$expected_pattern"; then
            log_success "PASSED"
            echo "Output matched: $expected_pattern"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            log_error "FAILED - Pattern not matched"
            echo "Expected: $expected_pattern"
            echo "Got: $output"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        log_error "FAILED - Command error"
        echo "Command: $test_command"
        echo "Output: $output"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

################################################################################
# Main Tests
################################################################################

echo ""
echo "================================================================"
echo "AWS VPC CNI (aws-node) Daemon Functionality Tests"
echo "================================================================"
echo ""
echo "Image: $IMAGE_NAME"
echo "Date: $(date)"
echo ""

# Pre-flight check
log_info "Checking if image exists..."
if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    log_error "Image '$IMAGE_NAME' not found!"
    exit 1
fi
log_success "Image found"

################################################################################
# Section 1: Entrypoint Validation
################################################################################

echo ""
echo "================================================================"
echo -e "${CYAN}[1/6] Entrypoint FIPS Validation${NC}"
echo "================================================================"

run_test \
    "Entrypoint script exists and is executable" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/entrypoint.sh && echo exists'" \
    "exists"

run_test \
    "Entrypoint validates OpenSSL version" \
    "docker run --rm --entrypoint=/app/entrypoint.sh $IMAGE_NAME /bin/bash 2>&1 | head -50" \
    "OpenSSL version.*3\.0\.15"

run_test \
    "Entrypoint checks wolfProvider" \
    "docker run --rm --entrypoint=/app/entrypoint.sh $IMAGE_NAME /bin/bash 2>&1 | head -50" \
    "wolfProvider is loaded and active"

run_test \
    "Entrypoint runs FIPS integrity check" \
    "docker run --rm --entrypoint=/app/entrypoint.sh $IMAGE_NAME /bin/bash 2>&1 | head -50" \
    "wolfSSL FIPS integrity check passed"

run_test \
    "Entrypoint tests SHA-256" \
    "docker run --rm --entrypoint=/app/entrypoint.sh $IMAGE_NAME /bin/bash 2>&1 | head -50" \
    "SHA-256 test passed"

run_test \
    "Entrypoint verifies binaries" \
    "docker run --rm --entrypoint=/app/entrypoint.sh $IMAGE_NAME /bin/bash 2>&1 | head -50" \
    "All AWS VPC CNI binaries found"

################################################################################
# Section 2: Binary Execution Tests
################################################################################

echo ""
echo "================================================================"
echo -e "${CYAN}[2/6] Binary Execution Tests${NC}"
echo "================================================================"

run_test \
    "aws-k8s-agent is dynamically linked binary" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-k8s-agent'" \
    "linux-vdso|libc\\.so|libpthread"

run_test \
    "aws-cni is dynamically linked binary" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-cni'" \
    "linux-vdso|libc\\.so|libpthread"

run_test \
    "egress-cni is dynamically linked binary" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/egress-cni'" \
    "linux-vdso|libc\\.so|libpthread"

run_test \
    "grpc-health-probe can show help" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c '/app/grpc-health-probe -help 2>&1'" \
    "Usage|help|grpc"

run_test \
    "aws-vpc-cni is dynamically linked binary" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-vpc-cni'" \
    "linux-vdso|libc\\.so|libpthread"

################################################################################
# Section 3: Network Tools Verification
################################################################################

echo ""
echo "================================================================"
echo -e "${CYAN}[3/6] Network Tools Verification${NC}"
echo "================================================================"

run_test \
    "iptables version" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'iptables --version 2>&1 || true'" \
    "iptables v"

run_test \
    "ip6tables version" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ip6tables --version 2>&1 || true'" \
    "ip6tables v"

run_test \
    "ipset version" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ipset --version 2>&1 || true'" \
    "ipset v"

run_test \
    "conntrack version" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'conntrack --version 2>&1 || true'" \
    "conntrack v"

run_test \
    "ip (iproute2) available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ip -V 2>&1 || ip help 2>&1 | head -1'" \
    "ip utility|Usage: ip"

run_test \
    "jq version" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'jq --version 2>&1 || true'" \
    "jq-"

run_test \
    "bash available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'bash --version 2>&1 || true'" \
    "GNU bash"

################################################################################
# Section 4: Configuration File Tests
################################################################################

echo ""
echo "================================================================"
echo -e "${CYAN}[4/6] Configuration File Tests${NC}"
echo "================================================================"

run_test \
    "CNI config file (10-aws.conflist) exists" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'cat /app/10-aws.conflist'" \
    "cniVersion|plugins"

run_test \
    "CNI config is valid JSON" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'jq . /app/10-aws.conflist > /dev/null && echo valid'" \
    "valid"

run_test \
    "ENI max pods file exists" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'cat /app/eni-max-pods.txt | head -5'" \
    "[0-9]+"

run_test \
    "OpenSSL config has wolfProvider" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'grep wolfprov /usr/local/openssl/ssl/openssl.cnf'" \
    "wolfprov"

################################################################################
# Section 5: Volume Mount Requirements
################################################################################

echo ""
echo "================================================================"
echo -e "${CYAN}[5/6] Volume Mount Requirements${NC}"
echo "================================================================"

log_info "Testing with temporary volume mounts..."
mkdir -p /tmp/cni-test-bin /tmp/cni-test-net /tmp/cni-test-log

run_test \
    "Container can write to CNI bin directory" \
    "docker run --rm --entrypoint=/bin/bash -v /tmp/cni-test-bin:/host/opt/cni/bin $IMAGE_NAME -c 'touch /host/opt/cni/bin/test && echo success'" \
    "success"

run_test \
    "Container can write to CNI net directory" \
    "docker run --rm --entrypoint=/bin/bash -v /tmp/cni-test-net:/host/etc/cni/net.d $IMAGE_NAME -c 'touch /host/etc/cni/net.d/test.conf && echo success'" \
    "success"

run_test \
    "Container can write to log directory" \
    "docker run --rm --entrypoint=/bin/bash -v /tmp/cni-test-log:/var/log/aws-routed-eni $IMAGE_NAME -c 'echo test > /var/log/aws-routed-eni/test.log && echo success'" \
    "success"

run_test \
    "Runtime directories are writable" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -w /var/run/aws-node && test -w /var/log/aws-routed-eni && echo writable'" \
    "writable"

# Cleanup
rm -rf /tmp/cni-test-bin /tmp/cni-test-net /tmp/cni-test-log

################################################################################
# Section 6: Health Probe Functionality
################################################################################

echo ""
echo "================================================================"
echo -e "${CYAN}[6/6] Health Probe Functionality${NC}"
echo "================================================================"

run_test \
    "grpc-health-probe binary is executable" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/grpc-health-probe && echo executable'" \
    "executable"

run_test \
    "grpc-health-probe shows usage" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c '/app/grpc-health-probe -help 2>&1'" \
    "Usage|addr|connect-timeout"

run_test \
    "grpc-health-probe can fail gracefully" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c '/app/grpc-health-probe -addr=localhost:50051 -connect-timeout=1s 2>&1 || echo failed'" \
    "failed|connection refused|timeout"

################################################################################
# Summary
################################################################################

echo ""
echo "================================================================"
echo "Test Summary"
echo "================================================================"
echo "Total tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    log_success "All daemon functionality tests passed!"
    echo ""
    log_info "The AWS VPC CNI daemon image is fully functional and ready for deployment."
    echo ""
    log_info "To run the daemon locally for testing:"
    echo "  docker run --rm --net=host --privileged \\"
    echo "    -e NODE_NAME=test-node \\"
    echo "    -v /tmp/cni-bin:/host/opt/cni/bin \\"
    echo "    -v /tmp/cni-net:/host/etc/cni/net.d \\"
    echo "    $IMAGE_NAME"
    echo ""
    exit 0
else
    log_error "Some daemon functionality tests failed!"
    echo ""
    log_info "Review the failed tests above and check:"
    echo "  - Image build completed successfully"
    echo "  - All binaries were built correctly"
    echo "  - Entrypoint script is present"
    echo "  - Network tools are installed"
    echo ""
    exit 1
fi
