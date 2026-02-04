# AWS VPC CNI (aws-node) v1.21.1 - FIPS 140-3 Compliant Image

This directory contains a FIPS 140-3 compliant Docker image for AWS VPC CNI (aws-node) v1.21.1, built using the architecture and best practices defined in `FIPS-DOCKER-BUILD-GUIDE.md`.

## Overview

**aws-node** (AWS VPC CNI) is the main networking plugin for Kubernetes on AWS. It runs as a DaemonSet on every node to:
- Manage IP address allocation for pods (IPAM via aws-k8s-agent)
- Attach and configure Elastic Network Interfaces (ENIs) to EC2 instances
- Route pod traffic through ENIs using AWS VPC networking
- Support security groups for pods and network policies
- Handle IPv4 and IPv6 networking

This FIPS-enabled version ensures all cryptographic operations (TLS connections to AWS APIs, EC2 metadata, etc.) use FIPS 140-3 validated cryptography.

### Build Variants

Two Dockerfiles are provided:
- **`Dockerfile`** - FIPS 140-3 compliant image
- **`Dockerfile.hardened`** - FIPS 140-3 compliant + DISA STIG and CIS security hardening

## Architecture

```
aws-vpc-cni components (5 Go binaries)
    ↓
golang-fips/go (FIPS-enabled Go toolchain)
    ↓
OpenSSL 3.0.15 (with FIPS module infrastructure)
    ↓
wolfProvider v1.1.0 (OpenSSL 3.x provider bridge)
    ↓
wolfSSL FIPS v5.8.2 (FIPS 140-3 Certificate #4718)
```

### Components Built

This image contains 5 FIPS-enabled binaries:

1. **aws-k8s-agent** - IPAM daemon that manages IP addresses and ENIs
2. **aws-cni** - CNI plugin for pod network setup (routed-eni-cni-plugin)
3. **egress-cni** - Egress CNI plugin for managing pod egress traffic
4. **grpc-health-probe** - gRPC health check utility
5. **aws-vpc-cni** - Entrypoint wrapper that starts aws-k8s-agent

### Key Features

- ✅ **FIPS 140-3 Compliance**: Uses wolfSSL FIPS v5 (Certificate #4718)
- ✅ **No Code Changes**: Standard Go `crypto/*` imports work as-is
- ✅ **100% FIPS Mode**: All non-FIPS crypto libraries removed
- ✅ **Ubuntu 22.04 Base**: Proven foundation with kernel 5.15+
- ✅ **Multi-Stage Build**: Optimized for security and size
- ✅ **Runtime Validation**: FIPS checks at container startup
- ✅ **Network Capability**: Full iptables, ipset, and conntrack support

## Prerequisites

### Required Files

Before building, ensure you have these files in this directory:

- ✅ `Dockerfile` - Multi-stage FIPS build (~800 lines, 6 stages)
- ✅ `Dockerfile.hardened` - Multi-stage FIPS + STIG/CIS hardened build
- ✅ `openssl-wolfprov.cnf` - OpenSSL configuration with wolfProvider
- ✅ `fips-startup-check.c` - wolfSSL FIPS integrity verification utility
- ✅ `entrypoint.sh` - FIPS validation wrapper script
- ✅ `wolfssl_password.txt` - Password for wolfSSL FIPS commercial package (**SECRET**)
- ✅ `build.sh` - Build automation script
- ✅ `build-hardened.sh` - Build automation script for Dockerfile.hardened

### Required Access

- **wolfSSL FIPS v5 Commercial Package**: You need authorized access to download the password-protected package from wolfssl.com
- **Docker BuildKit**: Required for secret mounting during build

### System Requirements

- Docker 20.10+ with BuildKit support
- 8GB+ RAM for build process
- 20GB+ free disk space
- Internet connection for downloading dependencies

## Build Instructions

### Using the Build Script (Recommended)

```bash
# Make build script executable
chmod +x build.sh

# Build the image
./build.sh

# Build with custom tag
./build.sh --tag my-registry.com/aws-cni-fips:v1.21.1

# Build and push to registry
./build.sh --push --registry my-registry.com
```

### Building Hardened Variant (Dockerfile.hardened)

To build with DISA STIG and CIS hardening:

```bash
# Make build script executable  
chmod +x build-hardened.sh

# Build hardened image
./build-hardened.sh
```

### Manual Build

#### 1. Enable Docker BuildKit

```bash
export DOCKER_BUILDKIT=1
```

#### 2. Build the Image

```bash
docker buildx build \
  --secret id=wolfssl_password,src=wolfssl_password.txt \
  -t amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -f Dockerfile .
```

For hardened build:

```bash
docker buildx build \
  --secret id=wolfssl_password,src=wolfssl_password.txt \
  -t amazon-k8s-cni:v1.21.1-ubuntu-22.04-fips \
  -f Dockerfile.hardened .
```

**Build Time**: Approximately 50-60 minutes (most time spent building golang-fips/go toolchain ~30-40 min)

#### 3. Verify the Build

```bash
# Check image size
docker images | grep amazon-k8s-cni-fips

# Run FIPS verification (using entrypoint bypass to avoid daemon startup)
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'openssl list -providers'

# Should show wolfprov provider active
```

## Usage

### Running Locally (Test)

For local testing to verify FIPS validation:

```bash
# Test FIPS validation only (skip daemon startup)
docker run --rm --entrypoint=/app/entrypoint.sh \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  /bin/bash

# Test daemon startup (requires --net=host --privileged)
docker run --rm --net=host --privileged \
  -e NODE_NAME=test-node \
  -e CLUSTER_NAME=test-cluster \
  -v /var/run/aws-node:/var/run/aws-node \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04
```

**Note**: The daemon requires AWS credentials and will attempt to connect to EC2 API. For full testing, run on an EC2 instance with appropriate IAM role.

### Running in Kubernetes (Production)

In production, aws-vpc-cni runs as a DaemonSet on every node. See `kubernetes-daemonset.yaml` for a complete example.

**Key configuration points**:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: aws-node
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - name: aws-node
        image: amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04
        securityContext:
          privileged: true  # Required for network namespace management
          capabilities:
            add: ["NET_ADMIN", "NET_RAW"]
        env:
        - name: AWS_VPC_K8S_CNI_LOGLEVEL
          value: DEBUG
        - name: AWS_VPC_ENI_MTU
          value: "9001"
        - name: ENABLE_POD_ENI
          value: "false"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CLUSTER_NAME
          value: "my-cluster"
        volumeMounts:
        - name: cni-bin-dir
          mountPath: /host/opt/cni/bin
        - name: cni-net-dir
          mountPath: /host/etc/cni/net.d
        - name: log-dir
          mountPath: /var/log/aws-routed-eni
          readOnly: false
        - name: dockershim
          mountPath: /var/run/dockershim.sock
        - name: xtables-lock
          mountPath: /run/xtables.lock
      hostNetwork: true  # Required for ENI management
      tolerations:
      - operator: Exists  # Run on all nodes
      serviceAccountName: aws-node
      volumes:
      - name: cni-bin-dir
        hostPath:
          path: /opt/cni/bin
      - name: cni-net-dir
        hostPath:
          path: /etc/cni/net.d
      - name: log-dir
        hostPath:
          path: /var/log/aws-routed-eni
          type: DirectoryOrCreate
      - name: dockershim
        hostPath:
          path: /var/run/dockershim.sock
      - name: xtables-lock
        hostPath:
          path: /run/xtables.lock
          type: FileOrCreate
```

### Environment Variables

#### AWS VPC CNI Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_VPC_K8S_CNI_LOGLEVEL` | `DEBUG` | Log level (DEBUG, INFO, WARN, ERROR) |
| `AWS_VPC_K8S_CNI_LOG_FILE` | `/var/log/aws-routed-eni/ipamd.log` | IPAM daemon log file |
| `AWS_VPC_K8S_PLUGIN_LOG_FILE` | `/var/log/aws-routed-eni/plugin.log` | CNI plugin log file |
| `AWS_VPC_K8S_PLUGIN_LOG_LEVEL` | `DEBUG` | CNI plugin log level |
| `AWS_VPC_ENI_MTU` | `9001` | MTU for pod interfaces |
| `AWS_VPC_K8S_CNI_VETHPREFIX` | `eni` | Prefix for veth interfaces |
| `ENABLE_POD_ENI` | `false` | Enable ENI per pod (security groups for pods) |
| `POD_SECURITY_GROUP_ENFORCING_MODE` | `standard` | Security group enforcement mode |
| `DISABLE_INTROSPECTION` | `false` | Disable introspection endpoint |
| `DISABLE_METRICS` | `false` | Disable metrics endpoint |
| `NODE_NAME` | *required* | Kubernetes node name |
| `CLUSTER_NAME` | *optional* | Cluster name for tagging |

#### FIPS-Specific Environment Variables

These are automatically set in both Dockerfiles:

| Variable | Value | Purpose |
|----------|-------|---------|
| `OPENSSL_CONF` | `/usr/local/openssl/ssl/openssl.cnf` | OpenSSL configuration with wolfProvider |
| `OPENSSL_MODULES` | `/usr/local/openssl/lib64/ossl-modules` | OpenSSL provider modules directory |
| `LD_LIBRARY_PATH` | `/usr/local/openssl/lib64:...` | Dynamic library search path |

## Verification

### Verify FIPS Mode is Active

```bash
# Check wolfProvider is loaded (bypass entrypoint to avoid daemon startup)
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'openssl list -providers'

# Should output:
# Providers:
#   wolfprov
#     name: wolfSSL provider
#     status: active
```

### Verify No Non-FIPS Crypto Libraries

```bash
# Scan for non-FIPS crypto libraries (should be empty)
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'find /usr/lib /lib -name "libgnutls*" -o -name "libnettle*"'

# Should return no results (empty output)
```

### Test FIPS Algorithms

```bash
# Test FIPS-approved algorithm (SHA-256)
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'echo "test" | openssl dgst -sha256'

# Should succeed and output hash

# Test AES-256 encryption
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'echo "test" | openssl enc -aes-256-cbc -K $(printf "0%.0s" {1..64}) -iv $(printf "0%.0s" {1..32}) | base64'

# Should succeed
```

### Verify Binary Linkage

```bash
# Check aws-k8s-agent linkage
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'ldd /app/aws-k8s-agent | head -20'

# Should show linkage to libc.so, libpthread
# golang-fips/go routes crypto/* to OpenSSL at runtime (CGO-based)

# Check aws-cni linkage
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'ldd /app/aws-cni | head -20'
```

### Verify Networking Tools

```bash
# Verify iptables is available
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'iptables --version'

# Verify ipset is available
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'ipset --version'

# Verify conntrack is available
docker run --rm --entrypoint=/bin/bash \
  amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 \
  -c 'conntrack --version'
```

## Troubleshooting

### Build Failures

#### "wolfProvider not loaded" Error

**Symptom**: Build fails at Step 3 (Pre-Installation FIPS Verification)

**Solution**:
1. Check that `openssl-wolfprov.cnf` is present and correctly configured
2. Verify wolfProvider was built successfully in Stage 3
3. Check that `OPENSSL_CONF` environment variable points to the config file

#### "wolfssl_password.txt: no such file" Error

**Symptom**: Build fails at Stage 2 (wolfSSL FIPS v5 build)

**Solution**:
1. Ensure `wolfssl_password.txt` exists in the build context
2. Verify the file contains only the password (no extra whitespace)
3. Check Docker BuildKit is enabled: `export DOCKER_BUILDKIT=1`

#### Out of Memory During Build

**Symptom**: Build fails during golang-fips/go compilation (Stage 4)

**Solution**:
1. Increase Docker memory limit to 8GB+ in Docker Desktop settings
2. Close other applications to free up RAM
3. Consider building on a machine with more memory

### Runtime Issues

#### "OpenSSL not working" Error

**Symptom**: Container fails to start with OpenSSL errors

**Solution**:
1. Verify `OPENSSL_CONF` environment variable is set
2. Check that OpenSSL config file exists: `/usr/local/openssl/ssl/openssl.cnf`
3. Ensure `LD_LIBRARY_PATH` includes FIPS OpenSSL libraries

#### "Cannot list network interfaces" Warning

**Symptom**: Entrypoint shows warning about network interfaces

**Solution**:
1. Run with `--net=host` for local testing
2. In Kubernetes, ensure `hostNetwork: true` is set
3. Verify container has `NET_ADMIN` and `NET_RAW` capabilities

#### "iptables not available" Error

**Symptom**: Container fails to start, iptables not found

**Solution**:
1. Run with `--privileged` flag for local testing
2. In Kubernetes, ensure `privileged: true` security context
3. Check that iptables package is installed in the image

#### AWS API Connection Failures

**Symptom**: Cannot connect to EC2 API or AWS services

**Solution**:
1. Verify the container is running on an EC2 instance with IAM role
2. Check IAM role has required permissions (ec2:*, eni:*, etc.)
3. Ensure IMDS is accessible: `curl http://169.254.169.254/latest/meta-data/`
4. Verify FIPS mode doesn't block TLS to AWS APIs (should work)

#### "aws-k8s-agent" Crashes on Startup

**Symptom**: Daemon starts but aws-k8s-agent crashes

**Solution**:
1. Check logs in `/var/log/aws-routed-eni/ipamd.log`
2. Verify `NODE_NAME` environment variable is set correctly
3. Ensure IAM permissions are sufficient
4. Check that ENIs can be attached to the instance (check instance type limits)

### FIPS Validation Issues

#### MD5 Still Works (Not Blocked)

**Symptom**: MD5 hashing succeeds when it should fail

**Explanation**: wolfProvider may allow MD5 in non-strict mode. This is acceptable as long as application code uses FIPS-approved algorithms.

**Verification**: Check that SHA-256 and AES-256 work correctly (these are FIPS-approved).

## Differences from Standard Image

This FIPS image differs from the standard AWS VPC CNI image in these ways:

| Aspect | Standard Image | FIPS Image | FIPS Image (Dockerfile.hardened) |
|--------|----------------|------------|----------------------------------|
| **Base Image** | Amazon Linux 2 | Ubuntu 22.04 | Ubuntu 22.04 |
| **CGO** | `CGO_ENABLED=0` (static) | `CGO_ENABLED=1` (dynamic) | `CGO_ENABLED=1` (dynamic) |
| **Crypto Library** | Standard Go crypto | wolfSSL FIPS v5 via golang-fips/go | wolfSSL FIPS v5 via golang-fips/go |
| **OpenSSL** | System OpenSSL | Custom OpenSSL 3.0.15 + wolfProvider | Custom OpenSSL 3.0.15 + wolfProvider |
| **Non-FIPS Libs** | Present (GnuTLS, Nettle) | Removed completely | Removed completely |
| **Binary Size** | Smaller (~100MB) | Larger (~200MB) due to FIPS libraries | Larger (~200MB) due to FIPS libraries |
| **FIPS Compliance** | No | Yes (FIPS 140-3 Certificate #4718) | Yes (FIPS 140-3 Certificate #4718) |
| **STIG/CIS** | No | No | Yes (DISA STIG + CIS hardening) |

## Compatibility

### Kernel Requirements

- **Minimum**: Linux kernel 4.6+ (for ENI support)
- **Recommended**: Linux kernel 5.10+ (for full network policy support)
- **Ubuntu 22.04**: Ships with kernel 5.15+ ✅

### AWS Compatibility

- ✅ Amazon EKS (all versions)
- ✅ Self-managed Kubernetes on EC2
- ✅ kOps 1.29+ (earlier versions had Ubuntu 22.04 compatibility issues, now fixed)

### Kubernetes Versions

Compatible with Kubernetes versions supported by AWS VPC CNI v1.21.1:
- Kubernetes 1.24+
- Kubernetes 1.25+
- Kubernetes 1.26+
- Kubernetes 1.27+
- Kubernetes 1.28+
- Kubernetes 1.29+
- Kubernetes 1.30+

### EC2 Instance Types

- ✅ All EC2 instance types with ENI support
- ✅ Nitro instances (recommended for better performance)
- ✅ Graviton instances (ARM64 - requires separate build for ARM64)

## Security Considerations

### Dockerfile.hardened Security Controls

The `Dockerfile.hardened` variant includes DISA STIG and CIS security hardening:

- Removal of unnecessary packages and services
- Secure file permissions
- Kernel parameter hardening
- Audit logging configuration
- Filesystem hardening

### Running as Root

**Note**: aws-node **requires root privileges** to:
- Manage network namespaces and network interfaces
- Configure iptables, ipset, and conntrack rules
- Attach and detach ENIs to/from EC2 instances
- Write CNI configuration files to `/etc/cni/net.d`

### Privileged Security Context

The DaemonSet **must run with `privileged: true`** and `hostNetwork: true` in Kubernetes. This is required by AWS VPC CNI design for ENI management.

### IAM Permissions Required

The aws-node DaemonSet requires an IAM role with these permissions:
- `ec2:AttachNetworkInterface`
- `ec2:CreateNetworkInterface`
- `ec2:DeleteNetworkInterface`
- `ec2:DescribeInstances`
- `ec2:DescribeNetworkInterfaces`
- `ec2:DetachNetworkInterface`
- `ec2:ModifyNetworkInterfaceAttribute`
- `ec2:AssignPrivateIpAddresses`
- `ec2:UnassignPrivateIpAddresses`

### Secret Management

**CRITICAL**: Never commit `wolfssl_password.txt` to version control!

Add to `.gitignore`:
```
wolfssl_password.txt
*.7z
```

## Build Artifacts

After a successful build, you'll have:

- Docker image: `amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04`
- Size: ~500-600MB (includes all FIPS libraries and networking tools)
- Layers: 35+ layers (multi-stage build optimized)

For hardened build (Dockerfile.hardened):
- Docker image: `amazon-k8s-cni:v1.21.1-ubuntu-22.04-fips`
- Includes STIG/CIS security hardening

## References

- **AWS VPC CNI**: https://github.com/aws/amazon-vpc-cni-k8s
- **FIPS Build Guide**: `../../FIPS-DOCKER-BUILD-GUIDE.md`
- **wolfSSL FIPS**: https://www.wolfssl.com/products/fips/
- **golang-fips**: https://github.com/golang-fips/go
- **OpenSSL 3**: https://www.openssl.org/

## Version Information

- **Component**: aws-node (AWS VPC CNI)
- **Version**: v1.21.1
- **Base Image**: Ubuntu 22.04
- **OpenSSL**: 3.0.15
- **wolfSSL FIPS**: v5.8.2 (Certificate #4718)
- **wolfProvider**: v1.1.0
- **Go**: golang-fips/go (go1.22-fips-release)

## License

This Dockerfile and supporting scripts are provided as-is for building FIPS-compliant images. The underlying aws-vpc-cni software is Apache 2.0 licensed by Amazon Web Services.

## Support

For issues related to:
- **FIPS build process**: Refer to `FIPS-DOCKER-BUILD-GUIDE.md`
- **aws-vpc-cni functionality**: https://github.com/aws/amazon-vpc-cni-k8s/issues
- **wolfSSL FIPS**: Contact wolfSSL commercial support
- **FIPS compliance questions**: Consult your security/compliance team

## Changelog

### v1.21.1-fips (2025-01-13)

- Initial FIPS-enabled build of aws-vpc-cni v1.21.1
- Based on FIPS-DOCKER-BUILD-GUIDE.md architecture
- Uses golang-fips/go with wolfSSL FIPS v5
- Ubuntu 22.04 base image
- Complete removal of non-FIPS crypto libraries
- CGO_ENABLED=1 for FIPS compliance (differs from upstream CGO_ENABLED=0)
- Includes all 5 aws-vpc-cni components: aws-k8s-agent, aws-cni, egress-cni, grpc-health-probe, aws-vpc-cni
