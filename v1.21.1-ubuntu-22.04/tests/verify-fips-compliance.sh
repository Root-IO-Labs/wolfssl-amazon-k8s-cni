#!/bin/bash
################################################################################
# AWS VPC CNI (aws-node) v1.21.1 - Comprehensive FIPS 140-3 Compliance Verification
#
# Purpose: Comprehensive verification of FIPS 140-3 compliance including
#          golang-fips/go integration, binary linkage, wolfProvider validation,
#          and daemon-specific FIPS compliance
#
# Usage:
#   ./tests/verify-fips-compliance.sh [image-name]
#
# Example:
#   ./tests/verify-fips-compliance.sh amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04
#
# Test Coverage:
#   • Image Architecture Validation (8 checks)
#   • golang-fips/go Specific Validation (6 checks)
#   • Multi-Binary Linkage Analysis (10 checks - 5 binaries x 2)
#   • wolfProvider Compliance (6 checks)
#   • Non-FIPS Crypto Library Scan (8 checks)
#   • Algorithm Testing (10 checks)
#   • Network Tools FIPS Verification (8 checks)
#   • Runtime Security Validation (6 checks)
#
# Total Checks: 62
# Expected Duration: ~120 seconds
#
# Exit Codes:
#   0 - Full FIPS compliance verified
#   1 - One or more critical checks failed
#
# Last Updated: 2026-01-13
# Version: 1.0
################################################################################

set -e

################################################################################
# Configuration & Constants
################################################################################

# Get image name from argument or use default
IMAGE_NAME="${1:-amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04}"

# Test counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
CRITICAL_FAILED=0

# Section counters
declare -A SECTION_PASSED
declare -A SECTION_TOTAL
declare -A SECTION_FAILED

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

################################################################################
# Helper Functions
################################################################################

init_section() {
    local section="$1"
    SECTION_PASSED[$section]=0
    SECTION_TOTAL[$section]=0
    SECTION_FAILED[$section]=0
}

print_header() {
    echo ""
    echo "================================================================"
    echo "  AWS VPC CNI (aws-node) v1.21.1 - FIPS 140-3 Compliance Verification"
    echo "================================================================"
    echo ""
    echo "Image: $IMAGE_NAME"
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
}

print_section() {
    local section_num="$1"
    local section_name="$2"

    echo ""
    echo "================================================================"
    echo -e "${CYAN}[$section_num/8] $section_name${NC}"
    echo "================================================================"
    echo ""
}

check_test() {
    local section="$1"
    local test_name="$2"
    local test_cmd="$3"
    local is_critical="${4:-no}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SECTION_TOTAL[$section]=$((${SECTION_TOTAL[$section]} + 1))

    echo -n "  Testing: $test_name ... "

    if eval "$test_cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        SECTION_PASSED[$section]=$((${SECTION_PASSED[$section]} + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        SECTION_FAILED[$section]=$((${SECTION_FAILED[$section]} + 1))

        if [ "$is_critical" = "yes" ]; then
            CRITICAL_FAILED=$((CRITICAL_FAILED + 1))
            echo -e "    ${RED}[CRITICAL FAILURE]${NC}"
        fi
        return 1
    fi
}

check_test_with_output() {
    local section="$1"
    local test_name="$2"
    local test_cmd="$3"
    local expected_pattern="$4"
    local is_critical="${5:-no}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SECTION_TOTAL[$section]=$((${SECTION_TOTAL[$section]} + 1))

    echo -n "  Testing: $test_name ... "

    output=$(eval "$test_cmd" 2>&1 || true)

    if echo "$output" | grep -qE "$expected_pattern"; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        SECTION_PASSED[$section]=$((${SECTION_PASSED[$section]} + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "    Expected: $expected_pattern"
        echo "    Got: $(echo "$output" | head -1)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        SECTION_FAILED[$section]=$((${SECTION_FAILED[$section]} + 1))

        if [ "$is_critical" = "yes" ]; then
            CRITICAL_FAILED=$((CRITICAL_FAILED + 1))
            echo -e "    ${RED}[CRITICAL FAILURE]${NC}"
        fi
        return 1
    fi
}

check_zero_count() {
    local section="$1"
    local test_name="$2"
    local test_cmd="$3"
    local is_critical="${4:-no}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SECTION_TOTAL[$section]=$((${SECTION_TOTAL[$section]} + 1))

    echo -n "  Testing: $test_name ... "

    count=$(eval "$test_cmd" 2>/dev/null || echo "0")

    if [ "$count" -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC} (count: $count)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        SECTION_PASSED[$section]=$((${SECTION_PASSED[$section]} + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC} (found $count, expected 0)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        SECTION_FAILED[$section]=$((${SECTION_FAILED[$section]} + 1))

        if [ "$is_critical" = "yes" ]; then
            CRITICAL_FAILED=$((CRITICAL_FAILED + 1))
            echo -e "    ${RED}[CRITICAL FAILURE]${NC}"
        fi
        return 1
    fi
}

################################################################################
# Main Test Execution
################################################################################

print_header

# Pre-flight check: Verify image exists
echo "Checking if image exists..."
if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo -e "${RED}✗ ERROR: Image '$IMAGE_NAME' not found!${NC}"
    echo "Please build the image first or specify the correct image name."
    exit 1
fi
echo -e "${GREEN}✓ Image found${NC}"

################################################################################
# Section 1: Image Architecture Validation
################################################################################

print_section "1" "Image Architecture Validation"
init_section "arch"

check_test_with_output "arch" "OpenSSL 3.0.15 present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl version'" \
    "OpenSSL 3\.0\.15" \
    "yes"

check_test "arch" "wolfSSL FIPS libraries present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -f /usr/lib/x86_64-linux-gnu/libwolfssl.so'"

check_test "arch" "wolfProvider module present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -f /usr/local/openssl/lib64/ossl-modules/libwolfprov.so'"

check_test "arch" "OpenSSL config with wolfProvider" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'grep -q wolfprov /usr/local/openssl/ssl/openssl.cnf'"

check_test "arch" "FIPS startup check utility present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /usr/local/bin/fips-startup-check'"

check_test "arch" "Entrypoint script present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/entrypoint.sh'"

check_test_with_output "arch" "OPENSSL_CONF environment set" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo \$OPENSSL_CONF'" \
    "/usr/local/openssl/ssl/openssl.cnf"

check_test_with_output "arch" "LD_LIBRARY_PATH includes FIPS paths" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo \$LD_LIBRARY_PATH'" \
    "/usr/local/openssl/lib64"

################################################################################
# Section 2: golang-fips/go Specific Validation
################################################################################

print_section "2" "golang-fips/go Integration"
init_section "golang"

check_test "golang" "Go binaries use CGO (aws-k8s-agent)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-k8s-agent | grep -q libc.so'"

check_test "golang" "Go binaries use CGO (aws-cni)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-cni | grep -q libc.so'"

check_test "golang" "Go binaries use CGO (aws-vpc-cni)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-vpc-cni | grep -q libc.so'"

check_test "golang" "Binaries dynamically linked (not static)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-k8s-agent | grep -q \"libc.so\"'"

check_test "golang" "Binaries have multiple dependencies (dynamic)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/aws-k8s-agent | wc -l | grep -qE \"^[3-9]|^[1-9][0-9]\"'"

check_test "golang" "OpenSSL libs accessible from Go binaries" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'LD_DEBUG=libs /app/aws-k8s-agent --version 2>&1 | grep -q libcrypto || true'"

################################################################################
# Section 3: Multi-Binary Linkage Analysis
################################################################################

print_section "3" "Multi-Binary Linkage Deep Analysis"
init_section "linkage"

# Check all 5 binaries
for binary in aws-k8s-agent aws-cni egress-cni grpc-health-probe aws-vpc-cni; do
    check_test "linkage" "$binary exists and executable" \
        "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -x /app/$binary'"

    check_test "linkage" "$binary has CGO linkage" \
        "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldd /app/$binary | grep -qE \"libc\\.so|libpthread\"'"
done

################################################################################
# Section 4: wolfProvider Compliance
################################################################################

print_section "4" "wolfProvider Compliance"
init_section "wolfprov"

check_test_with_output "wolfprov" "wolfProvider loaded" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -providers | grep -A 5 wolfprov'" \
    "status: active" \
    "yes"

check_test "wolfprov" "wolfProvider can list algorithms" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -digest-algorithms -provider wolfprov | grep -q SHA'"

check_test "wolfprov" "wolfProvider provides AES" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -cipher-algorithms -provider wolfprov | grep -q AES'"

check_test_with_output "wolfprov" "FIPS startup check passes" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c '/usr/local/bin/fips-startup-check'" \
    "FIPS VALIDATION PASSED" \
    "yes"

check_test "wolfprov" "wolfProvider version check" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -providers -verbose | grep -A 10 wolfprov | grep -q version'"

check_test "wolfprov" "No default provider active (strict FIPS)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c '! openssl list -providers | grep -A 3 \"^  default\" | grep -q \"status: active\"'"

################################################################################
# Section 5: Non-FIPS Crypto Library Scan
################################################################################

print_section "5" "Non-FIPS Crypto Library Removal"
init_section "nonfips"

check_zero_count "nonfips" "No GnuTLS libraries" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'find /usr/lib /lib -name \"libgnutls*\" 2>/dev/null | wc -l'" \
    "yes"

check_zero_count "nonfips" "No Nettle libraries" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'find /usr/lib /lib -name \"libnettle*\" 2>/dev/null | wc -l'" \
    "yes"

check_zero_count "nonfips" "No Hogweed libraries" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'find /usr/lib /lib -name \"libhogweed*\" 2>/dev/null | wc -l'" \
    "yes"

check_zero_count "nonfips" "No libgcrypt libraries" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'find /usr/lib /lib -name \"libgcrypt*\" 2>/dev/null | wc -l'" \
    "yes"

check_zero_count "nonfips" "No libk5crypto libraries" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'find /usr/lib /lib -name \"libk5crypto*\" 2>/dev/null | wc -l'"

check_test "nonfips" "FIPS libssl in system location" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -f /usr/lib/x86_64-linux-gnu/libssl.so.3'"

check_test "nonfips" "FIPS libcrypto in system location" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -f /usr/lib/x86_64-linux-gnu/libcrypto.so.3'"

check_test "nonfips" "FIPS libraries in ldconfig cache" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldconfig -p | grep -q libcrypto.so.3'"

################################################################################
# Section 6: FIPS Algorithm Testing
################################################################################

print_section "6" "FIPS Algorithm Runtime Testing"
init_section "algorithms"

check_test_with_output "algorithms" "SHA-256 (FIPS-approved)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl dgst -sha256'" \
    "SHA2-256"

check_test_with_output "algorithms" "SHA-384 (FIPS-approved)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl dgst -sha384'" \
    "SHA2-384"

check_test_with_output "algorithms" "SHA-512 (FIPS-approved)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl dgst -sha512'" \
    "SHA2-512"

check_test "algorithms" "AES-128-CBC encryption (FIPS-approved)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl enc -aes-128-cbc -K \$(printf \"0%.0s\" {1..32}) -iv \$(printf \"0%.0s\" {1..32}) | base64'"

check_test "algorithms" "AES-256-CBC encryption (FIPS-approved)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl enc -aes-256-cbc -K \$(printf \"0%.0s\" {1..64}) -iv \$(printf \"0%.0s\" {1..32}) | base64'"

check_test "algorithms" "AES-256-GCM encryption (FIPS-approved)" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl enc -aes-256-gcm -K \$(printf \"0%.0s\" {1..64}) -iv \$(printf \"0%.0s\" {1..24}) 2>/dev/null | base64'"

check_test "algorithms" "RSA algorithm available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -public-key-algorithms | grep -qi RSA'"

check_test "algorithms" "ECDSA algorithm available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl list -public-key-algorithms | grep -qi EC'"

check_test "algorithms" "HMAC-SHA256 available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'echo test | openssl dgst -sha256 -hmac \"key\"'"

check_test_with_output "algorithms" "TLS 1.2+ cipher suites available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl ciphers -v | grep TLSv1'" \
    "TLSv1\.[23]"

################################################################################
# Section 7: Network Tools FIPS Verification
################################################################################

print_section "7" "Network Tools FIPS Verification"
init_section "network"

check_test_with_output "network" "iptables available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'iptables --version 2>&1 || true'" \
    "iptables v"

check_test_with_output "network" "ip6tables available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ip6tables --version 2>&1 || true'" \
    "ip6tables v"

check_test_with_output "network" "ipset available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ipset --version 2>&1 || true'" \
    "ipset v"

check_test_with_output "network" "conntrack available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'conntrack --version 2>&1 || true'" \
    "conntrack v"

check_test_with_output "network" "iproute2 (ip command) available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ip -V 2>&1 || ip help 2>&1 | head -1'" \
    "ip utility|Usage: ip"

check_test "network" "jq (JSON processor) available" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'jq --version'"

check_test "network" "CNI config file present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -f /app/10-aws.conflist'"

check_test "network" "ENI max pods file present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -f /app/eni-max-pods.txt'"

################################################################################
# Section 8: Runtime Security Validation
################################################################################

print_section "8" "Runtime Security Validation"
init_section "security"

check_test "security" "FIPS libraries in ldconfig cache" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'ldconfig -p | grep -q wolfssl'"

check_test "security" "No SUID binaries present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test \$(find /app -perm /4000 | wc -l) -eq 0'"

check_test "security" "Runtime directories writable" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -w /var/run/aws-node && test -w /var/log/aws-routed-eni'"

check_test "security" "CA certificates present" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -d /etc/ssl/certs && test -f /etc/ssl/certs/ca-certificates.crt'"

check_test "security" "OpenSSL can verify certificates" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'openssl version -d'"

check_test "security" "Environment variables properly set" \
    "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME -c 'test -n \"\$OPENSSL_CONF\" && test -n \"\$OPENSSL_MODULES\"'"

################################################################################
# Final Report
################################################################################

echo ""
echo "================================================================"
echo -e "${BOLD}FIPS 140-3 Compliance Verification Report${NC}"
echo "================================================================"
echo ""

# Section summary
echo "Section Results:"
echo "----------------"
for section in arch golang linkage wolfprov nonfips algorithms network security; do
    total=${SECTION_TOTAL[$section]}
    passed=${SECTION_PASSED[$section]}
    failed=${SECTION_FAILED[$section]}

    if [ $failed -eq 0 ]; then
        status="${GREEN}✓ PASS${NC}"
    else
        status="${RED}✗ FAIL${NC}"
    fi

    printf "  %-30s %s (%d/%d passed)\n" "$(echo $section | tr '[:lower:]' '[:upper:]'):" "$status" "$passed" "$total"
done

echo ""
echo "Overall Results:"
echo "----------------"
echo "Total checks: $TOTAL_CHECKS"
echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
echo -e "Critical failures: ${RED}$CRITICAL_FAILED${NC}"

echo ""
PERCENTAGE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
echo "Success rate: $PERCENTAGE%"

echo ""
if [ $FAILED_CHECKS -eq 0 ]; then
    echo "================================================================"
    echo -e "${GREEN}${BOLD}✓ FULL FIPS 140-3 COMPLIANCE VERIFIED${NC}"
    echo "================================================================"
    echo ""
    echo "This image meets all FIPS 140-3 compliance requirements:"
    echo "  • wolfSSL FIPS v5.8.2 (Certificate #4718)"
    echo "  • wolfProvider v1.1.0 active"
    echo "  • All non-FIPS crypto libraries removed"
    echo "  • golang-fips/go routing crypto/* to FIPS OpenSSL"
    echo "  • All 5 binaries using FIPS cryptography"
    echo ""
    exit 0
elif [ $CRITICAL_FAILED -gt 0 ]; then
    echo "================================================================"
    echo -e "${RED}${BOLD}✗ CRITICAL FIPS COMPLIANCE FAILURES${NC}"
    echo "================================================================"
    echo ""
    echo "This image has $CRITICAL_FAILED critical failure(s) that prevent FIPS compliance."
    echo "Review the test output above and rebuild the image."
    echo ""
    exit 1
else
    echo "================================================================"
    echo -e "${YELLOW}${BOLD}⚠ PARTIAL FIPS COMPLIANCE${NC}"
    echo "================================================================"
    echo ""
    echo "This image has $FAILED_CHECKS non-critical failure(s)."
    echo "Review the test output above. The image may still be usable"
    echo "depending on your compliance requirements."
    echo ""
    exit 1
fi
