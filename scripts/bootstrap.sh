#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo "QuantumVault Environment Bootstrap Script"
echo "========================================="

# Update package index
echo "Updating apt package index..."
sudo apt-get update

# Install system dependencies
echo "Installing build essentials, CMake, Ninja, FUSE3 development headers, and other utilities..."
sudo apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    libfuse3-dev \
    pkg-config \
    git \
    curl

# Install Rust toolchain non-interactively if cargo is not found
if ! command -v cargo &> /dev/null; then
    echo "Rust/Cargo not found. Installing Rust toolchain via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
else
    echo "Rust/Cargo is already installed: $(cargo --version)"
fi

echo "========================================="
echo "Bootstrap complete! Verification:"
echo "-----------------------------------------"
echo "gcc version:   $(gcc --version | head -n1)"
echo "cmake version: $(cmake --version | head -n1)"
echo "ninja version: $(ninja --version | head -n1)"
echo "pkg-config:    $(pkg-config --version)"
echo "cargo version: $(cargo --version)"
echo "========================================="
echo "Environment is ready to build QuantumVault."
