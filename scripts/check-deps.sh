#!/usr/bin/env bash
set -euo pipefail

required=(cargo rustc clang)
missing=()

for cmd in "${required[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done

if [ ${#missing[@]} -ne 0 ]; then
  echo "Missing required tools: ${missing[*]}"
  echo "Please install them (e.g. via your distro package manager or rustup)."
  exit 1
fi

echo "All required tools present: ${required[*]}"
