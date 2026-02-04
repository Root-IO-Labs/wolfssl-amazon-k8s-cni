# AWS VPC CNI (aws-node) v1.21.1 - FIPS Test Suite

Comprehensive test suite for validating FIPS 140-3 compliance and functionality of the AWS VPC CNI (aws-node) FIPS-enabled Docker image.

## Overview

This test suite provides **149+ validation checks** across 5 test suites to ensure:
- FIPS 140-3 cryptographic compliance
- wolfProvider integration and activation
- All non-FIPS crypto libraries removed
- golang-fips/go integration for all 5 binaries
- Daemon functionality and network tools
- Algorithm blocking and approval

## Quick Start

```bash
# Run all tests (recommended)
./tests/run-all-tests.sh

# Or run a specific test suite
./tests/quick-test.sh
./tests/verify-fips-compliance.sh
./tests/test-cni-daemon-functionality.sh
./tests/check-non-fips-algorithms.sh
./tests/crypto-path-validation.sh
```

## Test Suites

### 1. quick-test.sh - Quick FIPS Validation

**Purpose**: Fast smoke test for core FIPS functionality
**Runtime**: ~20 seconds
**Checks**: 12

Quick validation of:
- ✓ OpenSSL 3.0.15 installation
- ✓ wolfProvider loaded and active
- ✓ FIPS startup check utility
- ✓ SHA-256 cryptographic operations
- ✓ No non-FIPS crypto libraries
- ✓ All 5 binaries present (aws-k8s-agent, aws-cni, egress-cni, grpc-health-probe, aws-vpc-cni)
- ✓ iptables/ipset/conntrack available
- ✓ CGO linkage for FIPS
- ✓ CNI configuration files

**Usage**:
```bash
./tests/quick-test.sh [image-name]
```

**Example**:
```bash
./tests/quick-test.sh amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04
```

---

### 2. verify-fips-compliance.sh - Comprehensive FIPS Compliance

**Purpose**: Exhaustive FIPS 140-3 compliance verification
**Runtime**: ~120 seconds
**Checks**: 62

Comprehensive validation across 8 categories:

#### Section 1: Image Architecture Validation (8 checks)
- OpenSSL 3.0.15 version
- wolfSSL FIPS libraries
- wolfProvider module
- Configuration files
- Environment variables

#### Section 2: golang-fips/go Integration (6 checks)
- CGO linkage for all binaries
- Dynamic linking (not static)
- PIE (Position Independent Executable)
- OpenSSL library accessibility

#### Section 3: Multi-Binary Linkage Analysis (10 checks)
- aws-k8s-agent linkage
- aws-cni linkage
- egress-cni linkage
- grpc-health-probe linkage
- aws-vpc-cni linkage

#### Section 4: wolfProvider Compliance (6 checks)
- Provider loaded and active
- Algorithm availability (SHA, AES)
- FIPS startup check passes
- Version verification
- No default provider active (strict FIPS)

#### Section 5: Non-FIPS Crypto Library Removal (8 checks)
- No GnuTLS
- No Nettle
- No Hogweed
- No libgcrypt
- No libk5crypto
- System OpenSSL removed
- FIPS libraries prioritized in ldconfig

#### Section 6: FIPS Algorithm Runtime Testing (10 checks)
- SHA-256, SHA-384, SHA-512 (approved)
- AES-128-CBC, AES-256-CBC, AES-256-GCM (approved)
- RSA operations
- ECDSA operations
- HMAC-SHA256
- TLS 1.2+ cipher suites

#### Section 7: Network Tools FIPS Verification (8 checks)
- iptables/ip6tables
- ipset
- conntrack
- iproute2 (ip command)
- jq (JSON processor)
- CNI config files

#### Section 8: Runtime Security Validation (6 checks)
- FIPS libraries in ldconfig
- No SUID binaries
- Runtime directories writable
- CA certificates present
- Certificate verification works
- Environment variables set

**Usage**:
```bash
./tests/verify-fips-compliance.sh [image-name]
```

---

### 3. test-cni-daemon-functionality.sh - Daemon Functionality Tests

**Purpose**: Test daemon-specific functionality
**Runtime**: ~60 seconds
**Checks**: 30

Validation across 6 categories:

#### Section 1: Entrypoint Validation (6 checks)
- Entrypoint script executable
- OpenSSL version validation
- wolfProvider check
- FIPS integrity check
- SHA-256 test
- Binary verification

#### Section 2: Binary Execution Tests (5 checks)
- aws-k8s-agent version/help
- aws-cni execution
- egress-cni execution
- grpc-health-probe help
- aws-vpc-cni binary check

#### Section 3: Network Tools Verification (8 checks)
- iptables/ip6tables versions
- ipset version
- conntrack version
- iproute2 (ip) version
- jq version
- bash available
- procps utilities

#### Section 4: Configuration File Tests (4 checks)
- CNI config file (10-aws.conflist) exists
- CNI config is valid JSON
- ENI max pods file exists
- OpenSSL config has wolfProvider

#### Section 5: Volume Mount Requirements (4 checks)
- CNI bin directory writable
- CNI net directory writable
- Log directory writable
- Runtime directories writable

#### Section 6: Health Probe Functionality (3 checks)
- grpc-health-probe executable
- Shows usage information
- Fails gracefully when daemon not running

**Usage**:
```bash
./tests/test-cni-daemon-functionality.sh [image-name]
```

---

### 4. check-non-fips-algorithms.sh - Non-FIPS Algorithm Blocking

**Purpose**: Verify non-FIPS algorithms are blocked
**Runtime**: ~30 seconds
**Checks**: 11

#### Test Suite 1: Blocked Hash Algorithms
- MD5 blocked
- MD4 blocked

#### Test Suite 2: Approved Hash Algorithms
- SHA-256 works
- SHA-384 works
- SHA-512 works

#### Test Suite 3: Encryption Algorithms
- AES-256-CBC works (FIPS-approved)
- AES-128-CBC works (FIPS-approved)

#### Test Suite 4: Library Removal Verification
- GnuTLS library removed
- Nettle library removed
- Hogweed library removed
- libgcrypt removed

**Usage**:
```bash
./tests/check-non-fips-algorithms.sh [image-name]
```

---

### 5. crypto-path-validation.sh - Cryptographic Path Validation

**Purpose**: Validate complete crypto path from binaries to wolfSSL
**Runtime**: ~30 seconds
**Checks**: 34

#### Test Suite 1: Multi-Binary Linkage Verification (15 checks)
- All 5 binaries exist and executable
- All 5 binaries built with CGO

#### Test Suite 2: Environment Configuration (4 checks)
- OPENSSL_CONF set
- OPENSSL_MODULES set
- LD_LIBRARY_PATH includes FIPS paths
- PATH includes FIPS OpenSSL binaries

#### Test Suite 3: OpenSSL Provider Verification (5 checks)
- OpenSSL 3.0.15 version
- wolfProvider loaded and active
- Config file exists
- wolfProvider module exists
- wolfProvider in openssl.cnf

#### Test Suite 4: wolfSSL Library Verification (4 checks)
- wolfSSL library exists
- wolfSSL in system location
- wolfSSL in ldconfig cache
- FIPS startup check utility exists

#### Test Suite 5: golang-fips/go Integration (4 checks)
- CGO compilation verified
- OpenSSL crypto operations work
- FIPS startup check passes

#### Test Suite 6: Configuration Files Verification (5 checks)
- CNI config exists
- CNI config valid JSON
- ENI max pods file exists
- Entrypoint script exists
- Runtime directories exist

**Usage**:
```bash
./tests/crypto-path-validation.sh [image-name]
```

---

### 6. run-all-tests.sh - Master Test Runner

**Purpose**: Run all test suites in sequence
**Runtime**: ~4-5 minutes
**Total Checks**: 149

Runs all 5 test suites and provides comprehensive report with:
- Individual suite pass/fail status
- Execution time per suite
- Total execution time
- Overall compliance summary

**Usage**:
```bash
./tests/run-all-tests.sh [image-name]
```

**Example Output**:
```
===============================================================================
Final Test Report
===============================================================================

Suite Results:
-------------
  Suite 1: ✓ PASSED (18s)
  Suite 2: ✓ PASSED (95s)
  Suite 3: ✓ PASSED (52s)
  Suite 4: ✓ PASSED (28s)
  Suite 5: ✓ PASSED (31s)

Overall Results:
----------------
Total Suites: 5
Passed: 5
Failed: 0
Total Time: 224s (3m 44s)

===============================================================================
✓ ALL TEST SUITES PASSED
===============================================================================
```

---

## Test Coverage Summary

| Test Suite | Runtime | Checks | Focus |
|------------|---------|--------|-------|
| quick-test.sh | ~20s | 12 | Smoke test |
| verify-fips-compliance.sh | ~120s | 62 | Comprehensive FIPS |
| test-cni-daemon-functionality.sh | ~60s | 30 | Daemon features |
| check-non-fips-algorithms.sh | ~30s | 11 | Algorithm blocking |
| crypto-path-validation.sh | ~30s | 34 | Crypto path |
| **TOTAL** | **~260s** | **149** | **Full coverage** |

## Exit Codes

All test scripts use consistent exit codes:
- `0` - All tests passed
- `1` - One or more tests failed

## Environment Requirements

- Docker 20.10+
- bash 4.0+
- ~2GB free disk space for test execution
- Network access (for Docker operations)

## Customizing Tests

### Using Custom Image Name

All tests accept an optional image name parameter:

```bash
./tests/quick-test.sh my-registry.com/aws-cni-fips:custom-tag
./tests/run-all-tests.sh my-registry.com/aws-cni-fips:custom-tag
```

### Modifying Test Thresholds

Edit the test scripts directly to adjust:
- Timeout values
- Expected patterns
- Pass/fail thresholds

## Troubleshooting

### "Image not found" Error

**Solution**: Build the image first
```bash
cd ../
./build.sh
```

### Tests Pass But Image Not FIPS Compliant

This should not happen if all tests pass. If you suspect an issue:

1. Run comprehensive test: `./tests/verify-fips-compliance.sh`
2. Check for critical failures
3. Verify wolfProvider is active: `docker run --rm --entrypoint=/bin/bash <image> -c 'openssl list -providers'`

### Slow Test Execution

Test execution time depends on:
- Docker image size (~500-600MB)
- System performance
- Docker disk I/O speed

Expected times:
- Fast system (SSD, 8+ cores): ~3-4 minutes total
- Slower system (HDD, 4 cores): ~5-7 minutes total

### Test Suite Hangs

If a test hangs:
1. Press Ctrl+C to cancel
2. Check Docker daemon: `docker ps`
3. Check for resource constraints: `docker stats`
4. Run individual test with verbose output

## CI/CD Integration

### GitLab CI Example

```yaml
test:fips-compliance:
  stage: test
  script:
    - cd amazon-k8s-cni/v1.21.1-fips
    - ./tests/run-all-tests.sh
  artifacts:
    when: always
    reports:
      junit: test-results.xml
```

### GitHub Actions Example

```yaml
- name: Run FIPS Compliance Tests
  run: |
    cd amazon-k8s-cni/v1.21.1-fips
    ./tests/run-all-tests.sh
```

### Jenkins Pipeline Example

```groovy
stage('FIPS Compliance Tests') {
    steps {
        sh '''
            cd amazon-k8s-cni/v1.21.1-fips
            ./tests/run-all-tests.sh
        '''
    }
}
```

## Test Development

### Adding New Tests

1. Create new test script in `tests/` directory
2. Follow naming convention: `test-<feature>.sh`
3. Use consistent exit codes (0 = pass, 1 = fail)
4. Add to `run-all-tests.sh`
5. Update this README

### Test Script Template

```bash
#!/bin/bash
# Test script template

IMAGE_NAME="${1:-amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04}"
FAILED=0
PASSED=0

# Your tests here
echo "Running tests..."

# Exit with appropriate code
if [ $FAILED -eq 0 ]; then
    echo "✓ ALL TESTS PASSED"
    exit 0
else
    echo "✗ TESTS FAILED"
    exit 1
fi
```

## References

- **FIPS Build Guide**: `../FIPS-DOCKER-BUILD-GUIDE.md`
- **Main README**: `../README.md`
- **Dockerfile**: `../Dockerfile`
- **wolfSSL FIPS**: https://www.wolfssl.com/products/fips/
- **golang-fips**: https://github.com/golang-fips/go

## Support

For issues with tests:
1. Check test output for specific errors
2. Review Dockerfile build logs
3. Verify image built successfully
4. Run individual test suites for detailed output
5. Check that Docker daemon is running properly

## Version History

- **v1.0** (2026-01-13): Initial test suite for aws-node v1.21.1
  - 5 test suites
  - 149 total checks
  - ~4-5 minute execution time
  - Comprehensive FIPS 140-3 validation
