#!/bin/bash
#
# Quick FIPS validation test for AWS VPC CNI (aws-node) v1.21.1
#
# This is a fast smoke test that validates the core FIPS configuration.
# Run this after building the image to quickly verify FIPS compliance.
#
# Usage: ./quick-test.sh [IMAGE_NAME]
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#

set -euo pipefail

# Default image name
DEFAULT_IMAGE="amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04"
IMAGE_NAME="${1:-${DEFAULT_IMAGE}}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Functions
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

run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    local failure_message="${4:-Test failed}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo ""
    echo "----------------------------------------"
    echo "Test $TOTAL_TESTS: $test_name"
    echo "----------------------------------------"

    if output=$(eval "$test_command" 2>&1); then
        if echo "$output" | grep -qE "$expected_pattern"; then
            log_success "PASSED: $test_name"
            echo "Output: $output"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            log_error "FAILED: $test_name"
            log_error "$failure_message"
            echo "Expected pattern: $expected_pattern"
            echo "Actual output: $output"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        log_error "FAILED: $test_name (command error)"
        echo "Command: $test_command"
        echo "Output: $output"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Banner
echo ""
echo "========================================"
echo "AWS VPC CNI (aws-node) Quick FIPS Test"
echo "========================================"
echo ""
echo "Image: $IMAGE_NAME"
echo "Date: $(date)"
echo ""

# Pre-flight check: Verify image exists
log_info "Checking if image exists..."
if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    log_error "Image '$IMAGE_NAME' not found!"
    log_error "Please build the image first or specify the correct image name."
    exit 1
fi
log_success "Image found"
echo ""

# Test 1: OpenSSL version
run_test \
    "OpenSSL version check" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl version'" \
    "OpenSSL 3\.0\.15" \
    "Expected OpenSSL 3.0.15"

# Test 2: wolfProvider loaded
run_test \
    "wolfProvider loaded check" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -providers | grep -A 5 wolfprov'" \
    "status: active" \
    "wolfProvider is not active"

# Test 3: FIPS startup check utility
run_test \
    "FIPS startup check utility" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c '/usr/local/bin/fips-startup-check'" \
    "FIPS VALIDATION PASSED" \
    "FIPS startup check failed"

# Test 4: SHA-256 test (FIPS-approved)
run_test \
    "SHA-256 cryptographic operation" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl dgst -sha256'" \
    "SHA2-256" \
    "SHA-256 operation failed"

# Test 5: No non-FIPS crypto libraries
run_test \
    "No GnuTLS library present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'find /usr/lib /lib -name \"libgnutls*\" 2>/dev/null | wc -l'" \
    "^0$" \
    "Found non-FIPS GnuTLS libraries"

# Test 6: aws-k8s-agent binary exists
run_test \
    "aws-k8s-agent binary exists" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/aws-k8s-agent && echo exists'" \
    "exists" \
    "aws-k8s-agent binary not found or not executable"

# Test 7: aws-cni binary exists
run_test \
    "aws-cni binary exists" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/aws-cni && echo exists'" \
    "exists" \
    "aws-cni binary not found or not executable"

# Test 8: aws-vpc-cni binary exists
run_test \
    "aws-vpc-cni binary exists" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/aws-vpc-cni && echo exists'" \
    "exists" \
    "aws-vpc-cni binary not found or not executable"

# Test 9: grpc-health-probe binary exists
run_test \
    "grpc-health-probe binary exists" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/grpc-health-probe && echo exists'" \
    "exists" \
    "grpc-health-probe binary not found or not executable"

# Test 10: iptables available
run_test \
    "iptables available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'iptables --version'" \
    "iptables v" \
    "iptables not available"

# Test 11: Binary linkage (CGO enabled)
run_test \
    "aws-k8s-agent has CGO linkage" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-k8s-agent | grep -E \"libc\\.so|libpthread\"'" \
    "libc\\.so" \
    "Binary does not show CGO linkage"

# Test 12: CNI config file exists
run_test \
    "CNI config file exists" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -f /app/10-aws.conflist && echo exists'" \
    "exists" \
    "CNI config file not found"

# Summary
echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Total tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    log_success "All quick tests passed!"
    echo ""
    log_info "Next steps:"
    echo "  1. Run comprehensive tests: ./tests/verify-fips-compliance.sh"
    echo "  2. Test daemon functionality: ./tests/test-cni-daemon-functionality.sh"
    echo "  3. Run all tests: ./tests/run-all-tests.sh"
    echo ""
    exit 0
else
    log_error "Some tests failed!"
    echo ""
    log_info "Troubleshooting:"
    echo "  - Check build logs for errors"
    echo "  - Verify wolfssl_password.txt is correct"
    echo "  - Ensure Docker BuildKit was enabled during build"
    echo "  - Run: docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -providers'"
    echo ""
    exit 1
fi
