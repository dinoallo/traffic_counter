#!/usr/bin/env bash
set -euo pipefail



# Check if Rust toolchain is installed
for cmd in cargo rustup rustc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: $cmd is not installed. Please install Rust from https://www.rust-lang.org/tools/install"
    exit 1
  fi
done

check_toolchain() {
    local channel=$1
    echo "Checking for toolchain: $channel..."
    
    # rustup toolchain list returns a list of installed toolchains.
    # We grep for the specific channel name.
    # The output is suppressed (2>/dev/null) to avoid error messages
    # if rustup itself is not installed, though the first check handles that.
    
    if rustup toolchain list | grep -q "^${channel}-"; then
        echo "✅ '$channel' toolchain is installed."
        return 0
    else
        echo "❌ '$channel' toolchain is NOT installed."
        return 1
    fi
}

# Check for stable and nightly toolchains
check_toolchain "stable"
check_toolchain "nightly"

# Check for required Rust components
check_component() {
    local channel=$1
    local comp=$2
    
    echo "Checking for component '$comp' on toolchain '$channel'..."

    # Check for the specific component on the installed toolchain
    # The grep pattern checks for the component name followed by "(installed)"
    if rustup component list --toolchain "$channel" | grep -q "^${comp}.*(installed)"; then
        echo "✅ '$comp' is installed for '$channel' toolchain."
        return 0
    else
        echo "❌ '$comp' is NOT installed for '$channel' toolchain."
        echo "   -> Run: rustup component add $comp --toolchain $channel"
        return 1
    fi
}

check_component "nightly" "rust-src"

# Check for other required tools
required=(bpftool bpf-linker)
missing=()

for cmd in "${required[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done

if [ ${#missing[@]} -ne 0 ]; then
  echo "Missing required tools: ${missing[*]}"
  echo "Please install them (e.g. via your distro package manager, rustup or cargo)."
  exit 1
fi

echo "All required tools present: ${required[*]}"
