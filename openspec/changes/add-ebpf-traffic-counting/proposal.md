# Change: Add eBPF traffic counting on the kernel side

## Why

Per-node traffic visibility is currently implemented primarily in userspace. Moving the primary counting work into the kernel (eBPF) reduces userspace overhead, increases accuracy at high packet rates, and enables low-latency, high-cardinality counters (per-IP and optional flow-level) with minimal packet-path work.

## What changes

- **ADD:** eBPF programs that increment per-IP (and optional flow) counters in-kernel.
- **ADD:** Stable eBPF map schemas (pinned under `/sys/fs/bpf/traffic_counter`) for counters and control state.
- **ADD:** Userspace helpers (loader/reader) to aggregate per-CPU counters, export metrics, and handle map migrations.
- **ADD:** Tests and validation harnesses to exercise eBPF programs in a privileged environment (VM/CI job).

**BREAKING:** none expected for userspace APIs if we keep map names and schemas stable; however, map layout changes will be breaking for pinned maps.

## Impact

- Affected specs: `traffic-observability` (new capability); update `openspec/specs/` accordingly.
- Affected code: `ebpf/` or `src/bpf/` (new kernel artifacts), userspace loader code in `src/`, build pipeline (`Makefile`, scripts/build-ebpf.sh).
- Deployment: requires nodes with kernel >= 5.4 (recommend testing at the minimum supported kernel) and capability to load eBPF programs (CAP_BPF, CAP_NET_ADMIN).

## Notes

- Prefer incremental rollout: ship eBPF program in passive (dry-run) mode, then enable production counters after verification.
- Keep map names and types stable; if schema changes are required, provide migration tooling or clear migration steps.
