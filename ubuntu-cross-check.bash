#!/bin/bash

set -euo pipefail

# Required packages 
# sudo apt update
# sudo apt install -y musl-tools mingw-w64

# Add cross-compilation toolchains
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-musl
rustup target add x86_64-pc-windows-gnu

# Cross-compile checks
echo "CHECKING GNU LINUX ..."
cargo check --target x86_64-unknown-linux-gnu
echo "CHECKING MUSL LINUX ..."
cargo check --target x86_64-unknown-linux-musl
echo "CHECKING WINDOWS ..."
RUSTFLAGS="-A unused -A dead_code" cargo check --target x86_64-pc-windows-gnu
echo "ALL CROSS CHECKS SUCCESSFUL!"
