#!/bin/bash
set -e

# $nv$ Protocol Shell Installer (for macOS/Darwin & Linux)
# Detects platform architecture, pulls target precompiled binary, and installs globally.

OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_NAME=linux;;
    Darwin*)    OS_NAME=macos;;
    *)          echo "Error: OS '${OS}' is not supported by this installer." && exit 1;;
esac

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)     ARCH_NAME=x64;;
    arm64|aarch64)  ARCH_NAME=arm64;;
    *)          echo "Error: Architecture '${ARCH}' is not supported by this installer." && exit 1;;
esac

# Define target release coordinates
REPO="oss-security/nv-protocol"
VERSION="v0.1.0"
BINARY_NAME="nv-${OS_NAME}-${ARCH_NAME}"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"

echo ">>> Fetching $nv$ protocol binary (${OS_NAME}-${ARCH_NAME}) from GitHub Releases..."

# Create clean temporary workspace
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Download using curl or wget fallback
if command -v curl >/dev/null 2>&1; then
    curl -L -o "$TMP_DIR/nv" "$URL"
elif command -v wget >/dev/null 2>&1; then
    wget -O "$TMP_DIR/nv" "$URL"
else
    echo "Error: Neither 'curl' nor 'wget' was found on your system. Please install one to continue."
    exit 1
fi

if [ ! -f "$TMP_DIR/nv" ]; then
    echo "Error: Download failed."
    exit 1
fi

# Relocate to global bin path
INSTALL_PATH="/usr/local/bin/nv"
echo ">>> Installing binary to ${INSTALL_PATH} (may prompt for sudo authorization)..."
sudo mv "$TMP_DIR/nv" "${INSTALL_PATH}"
sudo chmod +x "${INSTALL_PATH}"

echo ">>> nv protocol installed successfully! Run 'nv' to get started."
