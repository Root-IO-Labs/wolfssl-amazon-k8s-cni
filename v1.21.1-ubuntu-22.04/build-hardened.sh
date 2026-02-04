#!/bin/bash
set -euo pipefail

################################################################################
# Build Script for FIPS-Hardened AWS VPC CNI Docker Image
################################################################################

# Configuration
IMAGE_NAME="amazon-k8s-cni"
VERSION="v1.21.1"
OS="ubuntu"
OS_VERSION="22.04"
SECURITY_SUFFIX="fips"

# Construct tag
TAG="${VERSION}-${OS}-${OS_VERSION}-${SECURITY_SUFFIX}"
FULL_IMAGE_NAME="${IMAGE_NAME}:${TAG}"

echo "========================================"
echo "Building Hardened FIPS Image"
echo "========================================"
echo "Image: ${FULL_IMAGE_NAME}"
echo "Dockerfile: Dockerfile.hardened"
echo ""

# Build with buildkit
export DOCKER_BUILDKIT=1

docker buildx build \
    --secret id=wolfssl_password,src=./wolfssl_password.txt \
    --progress=plain \
    --tag "${FULL_IMAGE_NAME}" \
    --file Dockerfile.hardened \
    . || {
        echo ""
        echo "========================================"
        echo -e "\033[0;31m✗ BUILD FAILED\033[0m"
        echo "========================================"
        exit 1
    }

echo ""
echo "========================================"
echo -e "\033[0;32m✓ BUILD SUCCESSFUL\033[0m"
echo "========================================"
echo ""
echo "Image: ${FULL_IMAGE_NAME}"
echo "Security: FIPS 140-3 + DISA STIG + CIS"
echo ""
echo "Next steps:"
echo "  1. Test FIPS compliance:"
echo "     docker run --rm ${FULL_IMAGE_NAME} fips-startup-check"
echo ""
echo "  2. Run compliance scan:"
echo "     ./scan-internal.sh ${FULL_IMAGE_NAME}"
echo ""
echo "  3. Interactive shell:"
echo "     docker run -it --rm ${FULL_IMAGE_NAME} bash"
echo ""
