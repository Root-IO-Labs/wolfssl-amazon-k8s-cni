# AWS VPC CNI (aws-node) v1.21.1 FIPS-enabled Image
# Using golang-fips/go + Ubuntu System OpenSSL 3.0.2 + wolfProvider + wolfSSL FIPS v5
#
# Architecture: aws-node (Go) → golang-fips/go → Ubuntu System OpenSSL 3.0.2 → wolfProvider → wolfSSL FIPS v5
#
# MULTI-ARCHITECTURE SUPPORT:
#   ✅ x86_64 (amd64): Fully supported
#   ✅ ARM64 (aarch64): Fully supported (Apple Silicon, AWS Graviton, Raspberry Pi)
#   - Automatic architecture detection at build time
#   - Dynamic library path configuration (x86_64-linux-gnu vs aarch64-linux-gnu)
#   - Architecture-appropriate Go bootstrap compiler
#   - Compatible with multi-arch Docker buildx
#
# Build time: ~45-50 minutes (25-35 min for Go toolchain build)
# CRITICAL: NO application code changes required - standard Go crypto/* imports work as-is
#
#
# Build command (single architecture):
#   DOCKER_BUILDKIT=1 docker build --secret id=wolfssl_password,src=wolfssl_password.txt \
#     -t amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 -f Dockerfile.new .
#
# Build command (multi-architecture with buildx):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --secret id=wolfssl_password,src=wolfssl_password.txt \
#     -t amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04 -f Dockerfile.new .
#
# Run command (example):
#   docker run --rm --net=host --privileged \
#     -v /var/run/aws-node:/var/run/aws-node \
#     amazon-k8s-cni-fips:v1.21.1-ubuntu-22.04

# ============================================================================
# Stage 1: Build wolfSSL FIPS v5
# ============================================================================
FROM ubuntu:22.04 AS wolfssl-builder

ENV DEBIAN_FRONTEND=noninteractive

# wolfSSL Configuration
ENV WOLFSSL_URL=https://www.wolfssl.com/comm/wolfssl/wolfssl-5.8.2-commercial-fips-v5.2.3.7z
ENV WOLFSSL_PREFIX=/usr/local

# Install build dependencies + Ubuntu System OpenSSL
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        autoconf \
        automake \
        libtool \
        p7zip-full \
        libssl-dev \
        pkg-config \
    ; \
    rm -rf /var/lib/apt/lists/*

# Download and build wolfSSL FIPS v5
# NOTE: Requires commercial wolfSSL FIPS package (password-protected 7z file)
RUN --mount=type=secret,id=wolfssl_password,required=true \
    set -eux; \
    mkdir -p /usr/src; \
    curl -fsSL "${WOLFSSL_URL}" -o /tmp/wolfssl.7z; \
    PASSWORD=$(cat /run/secrets/wolfssl_password | tr -d '\n\r'); \
    7z x /tmp/wolfssl.7z -o/usr/src -p"${PASSWORD}"; \
    rm /tmp/wolfssl.7z; \
    find /usr/src -maxdepth 1 -type d -name "wolfssl*" -exec mv {} /usr/src/wolfssl \;; \
    cd /usr/src/wolfssl; \
    # Configure wolfSSL with FIPS v5 and necessary features
    # CLIENT FEEDBACK FIX: Removed --enable-des3, changed RSA_MIN_SIZE to 2048
    ./configure \
        --prefix=${WOLFSSL_PREFIX} \
        --enable-fips=v5 \
        --enable-opensslcoexist \
        --enable-cmac \
        --enable-keygen \
        --enable-sha \
        --enable-aesctr \
        --enable-aesccm \
        --enable-x963kdf \
        --enable-compkey \
        --enable-certgen \
        --enable-aeskeywrap \
        --enable-enckeys \
        --enable-base16 \
        --with-eccminsz=192 \
        CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DHAVE_PUBLIC_FFDHE -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DRSA_MIN_SIZE=2048" \
    ; \
    make -j"$(nproc)"; \
    ./fips-hash.sh; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    cd /; \
    rm -rf /usr/src/wolfssl; \
    echo "wolfSSL FIPS v5 installed successfully"

# Build FIPS startup check utility
COPY fips-startup-check.c /tmp/fips-startup-check.c
RUN set -eux; \
    gcc /tmp/fips-startup-check.c -o /usr/local/bin/fips-startup-check \
        -lwolfssl -I${WOLFSSL_PREFIX}/include; \
    chmod +x /usr/local/bin/fips-startup-check; \
    rm /tmp/fips-startup-check.c; \
    echo "FIPS startup check utility built successfully"

# ============================================================================
# Stage 2: Build wolfProvider
# ============================================================================
FROM ubuntu:22.04 AS wolfprov-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV WOLFSSL_PREFIX=/usr/local

# Install build dependencies + Ubuntu System OpenSSL
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        autoconf \
        automake \
        libtool \
        pkg-config \
        libssl-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

# Copy wolfSSL from previous stage
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/include/wolfssl ${WOLFSSL_PREFIX}/include/wolfssl
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/lib/libwolfssl.* ${WOLFSSL_PREFIX}/lib/

# Build wolfProvider v1.1.0
RUN set -eux; \
    git clone --depth 1 --branch v1.1.0 \
        https://github.com/wolfSSL/wolfProvider.git /tmp/wolfProvider; \
    cd /tmp/wolfProvider; \
    # Detect architecture for multi-arch support
    ARCH=$(uname -m); \
    echo "Building wolfProvider for architecture: $ARCH"; \
    if [ "$ARCH" = "x86_64" ]; then \
        MULTIARCH="x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        MULTIARCH="aarch64-linux-gnu"; \
    else \
        MULTIARCH="x86_64-linux-gnu"; \
    fi; \
    echo "Using multiarch path: $MULTIARCH"; \
    ./autogen.sh; \
    ./configure \
        --with-openssl=/usr \
        --with-wolfssl=${WOLFSSL_PREFIX} \
        --prefix=/usr/local \
        LDFLAGS="-L${WOLFSSL_PREFIX}/lib -L/usr/lib/${MULTIARCH}"; \
    make -j"$(nproc)"; \
    make install; \
    mkdir -p /usr/lib/${MULTIARCH}/ossl-modules; \
    if [ -f ".libs/libwolfprov.so" ]; then \
        cp -v .libs/libwolfprov.so* /usr/lib/${MULTIARCH}/ossl-modules/; \
    elif [ -f "src/.libs/libwolfprov.so" ]; then \
        cp -v src/.libs/libwolfprov.so* /usr/lib/${MULTIARCH}/ossl-modules/; \
    fi; \
    ls -la /usr/lib/${MULTIARCH}/ossl-modules/; \
    cd /; \
    rm -rf /tmp/wolfProvider; \
    echo "wolfProvider v1.1.0 installed successfully for $ARCH"

# Verify wolfProvider was built
RUN set -eux; \
    ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then MULTIARCH="x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MULTIARCH="aarch64-linux-gnu"; \
    else MULTIARCH="x86_64-linux-gnu"; fi; \
    ls -la /usr/lib/${MULTIARCH}/ossl-modules/; \
    if [ -f "/usr/lib/${MULTIARCH}/ossl-modules/libwolfprov.so" ]; then \
        echo "✓ wolfProvider built successfully"; \
    else \
        echo "✗ ERROR: wolfProvider not found!"; \
        exit 1; \
    fi

# ============================================================================
# Stage 3: Build golang-fips/go toolchain
# ============================================================================
FROM ubuntu:22.04 AS go-builder

ENV DEBIAN_FRONTEND=noninteractive

# Go Configuration
# CLIENT FEEDBACK FIX: Updated to go1.25-fips-release, added GOTOOLCHAIN=local
ENV GOLANG_FIPS_VERSION=go1.25-fips-release
ENV GOLANG_FIPS_REPO=https://github.com/golang-fips/go.git
ENV GOROOT_BOOTSTRAP=/usr/local/go-bootstrap
ENV GOROOT=/usr/local/go-fips
ENV GOTOOLCHAIN=local
ENV WOLFSSL_PREFIX=/usr/local

# Copy wolfSSL and wolfProvider from previous stages
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/include/wolfssl ${WOLFSSL_PREFIX}/include/wolfssl
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/lib/libwolfssl.* ${WOLFSSL_PREFIX}/lib/

# Copy wolfProvider (architecture-aware)
RUN --mount=type=bind,from=wolfprov-builder,source=/usr/lib,target=/mnt/wolfprov-lib \
    set -eux; \
    ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then MULTIARCH="x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MULTIARCH="aarch64-linux-gnu"; \
    else MULTIARCH="x86_64-linux-gnu"; fi; \
    mkdir -p /usr/lib/${MULTIARCH}/ossl-modules; \
    if [ -d "/mnt/wolfprov-lib/${MULTIARCH}/ossl-modules" ]; then \
        cp -v /mnt/wolfprov-lib/${MULTIARCH}/ossl-modules/libwolfprov.so* /usr/lib/${MULTIARCH}/ossl-modules/; \
    else \
        echo "ERROR: wolfProvider not found for $MULTIARCH"; \
        exit 1; \
    fi; \
    ls -la /usr/lib/${MULTIARCH}/ossl-modules/

# Install build dependencies + Ubuntu System OpenSSL
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        curl \
        pkg-config \
        libssl-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

# Install standard Go as bootstrap compiler
# CLIENT FEEDBACK FIX: Updated to Go 1.22.6 (required for go1.25-fips-release)
RUN set -eux; \
    ARCH=$(uname -m); \
    echo "Downloading Go bootstrap compiler for architecture: $ARCH"; \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        GO_ARCH="arm64"; \
    else \
        GO_ARCH="amd64"; \
    fi; \
    echo "Using Go architecture: $GO_ARCH"; \
    curl -fsSL https://go.dev/dl/go1.22.6.linux-${GO_ARCH}.tar.gz -o /tmp/go.tar.gz; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    mv /usr/local/go ${GOROOT_BOOTSTRAP}; \
    rm /tmp/go.tar.gz; \
    echo "✓ Go bootstrap 1.22.6 installed for $ARCH"

# Set up library paths (Ubuntu system paths)
ENV LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:/usr/lib/aarch64-linux-gnu:${WOLFSSL_PREFIX}/lib"
ENV PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:${WOLFSSL_PREFIX}/lib/pkgconfig"

# Build golang-fips/go from source with comprehensive ChaCha20 removal
RUN set -eux; \
    unset GOROOT; \
    export PATH="${GOROOT_BOOTSTRAP}/bin:${PATH}"; \
    git config --global user.email "builder@fips.local"; \
    git config --global user.name "FIPS Builder"; \
    git clone --branch ${GOLANG_FIPS_VERSION} ${GOLANG_FIPS_REPO} /tmp/go-fips-repo; \
    cd /tmp/go-fips-repo; \
    git submodule update --init --recursive; \
    cd /tmp/go-fips-repo; \
    ./scripts/full-initialize-repo.sh; \
    echo ""; \
    echo "========================================"; \
    echo "CRITICAL FIX: Removing TLS 1.3 ChaCha20-Poly1305 (Non-FIPS)"; \
    echo "========================================"; \
    echo "Background: Previous patch file approach was problematic"; \
    echo "  - Patch written for upstream Go but applied to golang-fips/go"; \
    echo "  - golang-fips patches modify cipher_suites.go, causing context mismatch"; \
    echo "  - Patch failures were silent, not build errors"; \
    echo ""; \
    echo "Solution: Use sed to directly remove ALL ChaCha20 references from crypto/tls"; \
    echo ""; \
    cd /tmp/go-fips-repo/go; \
    echo "  - Removing TLS 1.3 ChaCha20-Poly1305 (non-FIPS) from crypto/tls..."; \
    cd src/crypto/tls; \
    for file in *.go; do \
        if [ -f "$file" ]; then \
            sed -i '/TLS_CHACHA20_POLY1305_SHA256/d' "$file"; \
        fi; \
    done; \
    cd ../../..; \
    if grep -r "TLS_CHACHA20_POLY1305_SHA256" src/crypto/tls/ 2>/dev/null; then \
        echo "ERROR: Failed to remove all ChaCha20-Poly1305 references!"; \
        grep -rn "TLS_CHACHA20_POLY1305_SHA256" src/crypto/tls/ || true; \
        exit 1; \
    fi; \
    echo "  ✓ ChaCha20-Poly1305 successfully removed from all crypto/tls files"; \
    echo "  ✓ TLS 1.3 will only use FIPS-approved AES-GCM cipher suites"; \
    echo "========================================"; \
    echo ""; \
    cd /tmp/go-fips-repo/go/src; \
    CGO_ENABLED=1 \
    CGO_CFLAGS="-I/usr/include -I${WOLFSSL_PREFIX}/include" \
    CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -L/usr/lib/aarch64-linux-gnu -L${WOLFSSL_PREFIX}/lib" \
    ./make.bash; \
    FINAL_GOROOT=/usr/local/go-fips; \
    mv /tmp/go-fips-repo/go ${FINAL_GOROOT}; \
    rm -rf /tmp/go-fips-repo; \
    ${FINAL_GOROOT}/bin/go version

# ============================================================================
# Stage 4: Build AWS VPC CNI v1.21.1 Components
# ============================================================================
FROM ubuntu:22.04 AS app-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOROOT=/usr/local/go-fips
ENV PATH="${GOROOT}/bin:${PATH}"
# CLIENT FEEDBACK FIX: Added GOTOOLCHAIN=local and GOLANG_FIPS=1
ENV GOTOOLCHAIN=local
ENV GOLANG_FIPS=1
ENV WOLFSSL_PREFIX=/usr/local

# Copy Go toolchain and libraries
COPY --from=go-builder ${GOROOT} ${GOROOT}
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/include/wolfssl ${WOLFSSL_PREFIX}/include/wolfssl
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/lib/libwolfssl.* ${WOLFSSL_PREFIX}/lib/

# Copy wolfProvider (architecture-aware)
RUN --mount=type=bind,from=wolfprov-builder,source=/usr/lib,target=/mnt/wolfprov-lib \
    set -eux; \
    ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then MULTIARCH="x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MULTIARCH="aarch64-linux-gnu"; \
    else MULTIARCH="x86_64-linux-gnu"; fi; \
    mkdir -p /usr/lib/${MULTIARCH}/ossl-modules; \
    cp -v /mnt/wolfprov-lib/${MULTIARCH}/ossl-modules/libwolfprov.so* /usr/lib/${MULTIARCH}/ossl-modules/; \
    echo "$ARCH" > /tmp/arch.txt

# Install build dependencies + Ubuntu System OpenSSL
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        pkg-config \
        libssl-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

# Register wolfSSL libraries with ldconfig
RUN set -eux; \
    ARCH=$(cat /tmp/arch.txt); \
    if [ "$ARCH" = "x86_64" ]; then SYSTEM_LIBDIR="/usr/lib/x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then SYSTEM_LIBDIR="/usr/lib/aarch64-linux-gnu"; \
    else SYSTEM_LIBDIR="/usr/lib"; fi; \
    cp -av ${WOLFSSL_PREFIX}/lib/libwolfssl.so* "$SYSTEM_LIBDIR/" || true; \
    echo "${WOLFSSL_PREFIX}/lib" > /etc/ld.so.conf.d/fips-wolfssl.conf; \
    echo "$SYSTEM_LIBDIR" >> /etc/ld.so.conf.d/fips-wolfssl.conf; \
    ldconfig

# Configure OpenSSL to use wolfProvider (FIPS mode)
COPY openssl-wolfprov.cnf /tmp/openssl-wolfprov.cnf
RUN set -eux; \
    ARCH=$(cat /tmp/arch.txt); \
    if [ "$ARCH" = "x86_64" ]; then MULTIARCH="x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MULTIARCH="aarch64-linux-gnu"; \
    else MULTIARCH="x86_64-linux-gnu"; fi; \
    sed "s|/usr/lib/x86_64-linux-gnu/|/usr/lib/${MULTIARCH}/|g" \
        /tmp/openssl-wolfprov.cnf > /etc/ssl/openssl.cnf

# CRITICAL: Set OPENSSL_CONF so golang-fips/go can find the FIPS provider
ENV OPENSSL_CONF="/etc/ssl/openssl.cnf"

# Set up library paths (Ubuntu system paths)
ENV LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:/usr/lib/aarch64-linux-gnu:${WOLFSSL_PREFIX}/lib"
ENV PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:${WOLFSSL_PREFIX}/lib/pkgconfig"

# Build configuration for FIPS
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/usr/include -I${WOLFSSL_PREFIX}/include"
ENV CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -L/usr/lib/aarch64-linux-gnu -L${WOLFSSL_PREFIX}/lib"

# Use direct module downloads to avoid TLS/ECDSA issues with proxy.golang.org in FIPS mode
ENV GOPROXY=direct

# Clone and build aws-vpc-cni-k8s v1.21.1
RUN set -eux; \
    echo "Cloning amazon-vpc-cni-k8s repository..."; \
    git clone --depth 1 --branch v1.21.1 \
        https://github.com/aws/amazon-vpc-cni-k8s.git /tmp/amazon-vpc-cni-k8s; \
    cd /tmp/amazon-vpc-cni-k8s; \
    echo "Building AWS VPC CNI v1.21.1 components with FIPS Go..."; \
    go version; \
    echo "Downloading dependencies..."; \
    go mod download; \
    mkdir -p /app; \
    \
    echo "Building aws-k8s-agent (IPAM daemon)..."; \
    go build -buildmode=pie \
        -ldflags="-s -w -X github.com/aws/amazon-vpc-cni-k8s/pkg/version/info.Version=v1.21.1" \
        -o /app/aws-k8s-agent \
        ./cmd/aws-k8s-agent; \
    \
    echo "Building aws-cni plugin..."; \
    go build -buildmode=pie \
        -ldflags="-s -w" \
        -o /app/aws-cni \
        ./cmd/routed-eni-cni-plugin; \
    \
    echo "Building egress-cni plugin..."; \
    go build -buildmode=pie \
        -ldflags="-s -w" \
        -o /app/egress-cni \
        ./cmd/egress-cni-plugin; \
    \
    echo "Building grpc-health-probe..."; \
    go build -buildmode=pie \
        -ldflags="-s -w" \
        -o /app/grpc-health-probe \
        ./cmd/grpc-health-probe; \
    \
    echo "Building aws-vpc-cni entrypoint..."; \
    go build -buildmode=pie \
        -ldflags="-s -w" \
        -o /app/aws-vpc-cni \
        ./cmd/aws-vpc-cni; \
    \
    echo "Copying configuration files..."; \
    cp -v misc/10-aws.conflist /app/10-aws.conflist; \
    cp -v misc/eni-max-pods.txt /app/eni-max-pods.txt; \
    \
    echo "Verifying binaries..."; \
    ls -lah /app/; \
    \
    echo "AWS VPC CNI components built successfully"; \
    cd /; \
    rm -rf /tmp/amazon-vpc-cni-k8s

# ============================================================================
# Stage 5: Runtime image
# ============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WOLFSSL_PREFIX=/usr/local

# ============================================================================
# CRITICAL: Installation Order for FIPS Compliance
# Following FIPS-DOCKER-BUILD-GUIDE.md requirements
# ============================================================================

# ----------------------------------------------------------------------------
# Step 0: Detect Runtime Architecture (CRITICAL for multi-arch support)
# ----------------------------------------------------------------------------
RUN set -eux; \
    ARCH=$(uname -m); \
    echo "Runtime Architecture: $ARCH"; \
    if [ "$ARCH" = "x86_64" ]; then \
        SYSTEM_LIBDIR="/usr/lib/x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        SYSTEM_LIBDIR="/usr/lib/aarch64-linux-gnu"; \
    else \
        SYSTEM_LIBDIR="/usr/lib"; \
    fi; \
    echo "$SYSTEM_LIBDIR" > /tmp/system_libdir.txt; \
    echo "$ARCH" > /tmp/arch.txt; \
    echo "System Library Directory: $SYSTEM_LIBDIR"

# ----------------------------------------------------------------------------
# Step 1: Copy FIPS Components BEFORE apt-get (CRITICAL)
# ----------------------------------------------------------------------------
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/lib/libwolfssl.* ${WOLFSSL_PREFIX}/lib/
COPY --from=wolfssl-builder ${WOLFSSL_PREFIX}/include/wolfssl ${WOLFSSL_PREFIX}/include/wolfssl
COPY --from=wolfssl-builder /usr/local/bin/fips-startup-check /usr/local/bin/fips-startup-check

# Copy wolfProvider (architecture-aware)
RUN --mount=type=bind,from=wolfprov-builder,source=/usr/lib,target=/mnt/wolfprov-lib \
    set -eux; \
    ARCH=$(cat /tmp/arch.txt); \
    if [ "$ARCH" = "x86_64" ]; then MULTIARCH="x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MULTIARCH="aarch64-linux-gnu"; \
    else MULTIARCH="x86_64-linux-gnu"; fi; \
    mkdir -p /usr/lib/${MULTIARCH}/ossl-modules; \
    cp -v /mnt/wolfprov-lib/${MULTIARCH}/ossl-modules/libwolfprov.so* /usr/lib/${MULTIARCH}/ossl-modules/; \
    ls -la /usr/lib/${MULTIARCH}/ossl-modules/

# ----------------------------------------------------------------------------
# Step 2: Install Ubuntu System OpenSSL (Runtime Only)
# CLIENT FEEDBACK FIX: Using Ubuntu APT, not custom build
# ----------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    ; \
    rm -rf /var/lib/apt/lists/*

# Install wolfSSL to system locations
RUN set -eux; \
    SYSTEM_LIBDIR=$(cat /tmp/system_libdir.txt); \
    cp -av ${WOLFSSL_PREFIX}/lib/libwolfssl.so* "$SYSTEM_LIBDIR/" || true; \
    echo "${WOLFSSL_PREFIX}/lib" > /etc/ld.so.conf.d/fips-wolfssl.conf; \
    echo "$SYSTEM_LIBDIR" >> /etc/ld.so.conf.d/fips-wolfssl.conf; \
    ldconfig; \
    echo "✓ wolfSSL FIPS libraries installed to system locations"

# ----------------------------------------------------------------------------
# Step 3: Copy and Configure OpenSSL Configuration
# CLIENT FEEDBACK FIX: Official wolfProvider format, provider named "fips"
# ----------------------------------------------------------------------------
COPY openssl-wolfprov.cnf /tmp/openssl-wolfprov.cnf

# Architecture-aware OpenSSL configuration
RUN set -eux; \
    ARCH=$(cat /tmp/arch.txt); \
    if [ "$ARCH" = "x86_64" ]; then MULTIARCH="x86_64-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MULTIARCH="aarch64-linux-gnu"; \
    else MULTIARCH="x86_64-linux-gnu"; fi; \
    echo "Configuring OpenSSL for architecture: $ARCH (multiarch: $MULTIARCH)"; \
    sed "s|/usr/lib/x86_64-linux-gnu/|/usr/lib/${MULTIARCH}/|g" \
        /tmp/openssl-wolfprov.cnf > /etc/ssl/openssl.cnf; \
    cat /etc/ssl/openssl.cnf; \
    echo "✓ OpenSSL configuration created at /etc/ssl/openssl.cnf"

# Set environment variables for FIPS mode
# CLIENT FEEDBACK FIX: Added GOLANG_FIPS=1, updated paths
ENV PATH="/usr/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:/usr/lib/aarch64-linux-gnu:${WOLFSSL_PREFIX}/lib:/usr/lib"
ENV OPENSSL_CONF="/etc/ssl/openssl.cnf"
ENV GOLANG_FIPS=1

# ----------------------------------------------------------------------------
# Step 4: Verify FIPS Setup BEFORE Installing Packages (CRITICAL)
# ----------------------------------------------------------------------------
RUN set -eux; \
    echo ""; \
    echo "========================================"; \
    echo "Pre-Installation FIPS Verification"; \
    echo "========================================"; \
    echo ""; \
    echo "OpenSSL Version:"; \
    openssl version; \
    echo ""; \
    echo "OpenSSL Provider List:"; \
    openssl list -providers; \
    echo ""; \
    echo "Checking wolfProvider status..."; \
    if openssl list -providers | grep -qi "wolfSSL Provider"; then \
        echo "✓ wolfProvider is loaded"; \
    else \
        echo "✗ ERROR: wolfProvider is NOT loaded!"; \
        echo "Available providers:"; \
        openssl list -providers; \
        exit 1; \
    fi; \
    echo ""; \
    echo "Verifying provider is named 'fips' (golang-fips/go requirement)..."; \
    if openssl list -providers | grep -q "^  fips$"; then \
        echo "✓ Provider correctly named 'fips'"; \
    else \
        echo "✗ ERROR: Provider not named 'fips'!"; \
        echo "golang-fips/go requires provider named 'fips'"; \
        exit 1; \
    fi; \
    echo ""; \
    echo "Running FIPS startup check utility..."; \
    /usr/local/bin/fips-startup-check; \
    echo ""; \
    echo "Testing OpenSSL SHA-256..."; \
    echo "test" | openssl dgst -sha256 -hex; \
    echo ""; \
    echo "========================================"; \
    echo "✓ FIPS Verification PASSED"; \
    echo "========================================"; \
    echo ""

# ----------------------------------------------------------------------------
# Step 5: Install Remaining Packages
# ----------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        ipset \
        conntrack \
        jq \
        procps \
    ; \
    rm -rf /var/lib/apt/lists/*

# Remove non-FIPS crypto libraries (paranoid security)
RUN set -eux; \
    apt-get purge -y --auto-remove \
        libgnutls30 \
        libnettle8 \
        libhogweed6 \
        libgcrypt20 \
    2>/dev/null || true

# ----------------------------------------------------------------------------
# Step 6: Copy Application Binaries
# ----------------------------------------------------------------------------
COPY --from=app-builder /app/aws-k8s-agent /app/aws-k8s-agent
COPY --from=app-builder /app/aws-cni /app/aws-cni
COPY --from=app-builder /app/egress-cni /app/egress-cni
COPY --from=app-builder /app/grpc-health-probe /app/grpc-health-probe
COPY --from=app-builder /app/aws-vpc-cni /app/aws-vpc-cni
COPY --from=app-builder /app/10-aws.conflist /app/10-aws.conflist
COPY --from=app-builder /app/eni-max-pods.txt /app/eni-max-pods.txt

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Make binaries executable
RUN chmod +x /app/aws-k8s-agent \
             /app/aws-cni \
             /app/egress-cni \
             /app/grpc-health-probe \
             /app/aws-vpc-cni

# ----------------------------------------------------------------------------
# Step 7: Security Hardening
# ----------------------------------------------------------------------------
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# ----------------------------------------------------------------------------
# Step 8: Create Runtime Directories
# CLIENT FEEDBACK FIX: Create directories required by aws-node daemon
# ----------------------------------------------------------------------------
RUN mkdir -p /var/run/aws-node /var/log/aws-routed-eni && \
    chmod 755 /var/run/aws-node /var/log/aws-routed-eni

# ----------------------------------------------------------------------------
# Step 9: Configure Application Environment
# ----------------------------------------------------------------------------
ENV AWS_VPC_K8S_CNI_LOGLEVEL=DEBUG
ENV AWS_VPC_K8S_CNI_LOG_FILE=/var/log/aws-routed-eni/ipamd.log
ENV AWS_VPC_ENI_MTU=9001
ENV AWS_VPC_K8S_PLUGIN_LOG_FILE=/var/log/aws-routed-eni/plugin.log
ENV AWS_VPC_K8S_PLUGIN_LOG_LEVEL=DEBUG
ENV DISABLE_INTROSPECTION=false
ENV DISABLE_METRICS=false
ENV AWS_VPC_K8S_CNI_VETHPREFIX=eni
ENV ENABLE_POD_ENI=false
ENV POD_SECURITY_GROUP_ENFORCING_MODE=standard

# ----------------------------------------------------------------------------
# Container Metadata and Entrypoint
# ----------------------------------------------------------------------------
LABEL maintainer="FIPS Compliance Team" \
      description="AWS VPC CNI (aws-node) v1.21.1 with FIPS 140-3 compliance (Ubuntu System OpenSSL)" \
      version="v1.21.1-fips" \
      fips.openssl="3.0.2-ubuntu-system" \
      fips.wolfssl="5.8.2-v5.2.3" \
      fips.wolfprovider="1.1.0" \
      fips.certificate="4718" \
      component="aws-node"

WORKDIR /app

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["aws-k8s-agent"]
