#!/usr/bin/env bash
set -euo pipefail

EBPF_DIR=${1:-traffic-counter-ebpf/contrib}
OUT_DIR=${2:-$EBPF_DIR/target/bpf}
CC=${CC:-clang}
CFLAGS=${CFLAGS:-"-O2 -target bpf -g -D__BPF_TRACING__"}

mkdir -p "$OUT_DIR"

shopt_present=false
if [ -n "$(command -v shopt 2>/dev/null)" ]; then
  shopt_present=true
fi

if $shopt_present; then
  shopt -s nullglob
fi

files=("$EBPF_DIR"/*.c)
if [ ${#files[@]} -eq 0 ]; then
  echo "No eBPF C sources found in '$EBPF_DIR' (nothing to build)."
  exit 0
fi

echo "Using CC=$CC"
for src in "${files[@]}"; do
  base=$(basename "$src" .c)
  out="$OUT_DIR/$base.o"
  echo "Compiling $src -> $out"
  $CC -O2 -target bpf -g -D__BPF_TRACING__ -c "$src" -o "$out"
done

echo "eBPF build complete -- objects in $OUT_DIR"
