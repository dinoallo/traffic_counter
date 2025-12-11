# Design: eBPF traffic counting (kernel-side)

## Context

We need low-overhead, high-throughput counters maintained in the kernel to capture accurate per-IP/network traffic volumes. Userspace should perform aggregation and export.

## Goals

- Minimal work in the fast path (parse headers, update counters)
- Keep data structures compact and pin maps for longevity
- Support IPv4 and IPv6 keys; make flow-key optional
- Make map schemas stable and documented

## Non-Goals

- Full packet inspection or payload parsing
- Stateful TCP reassembly

## Decisions

- Attach point: prefer XDP for performance. Provide `tc` fallback for setups where XDP cannot be used.
- Map types:
  - Per-IP counters: `BPF_MAP_TYPE_PERCPU_HASH` keyed by `u128` (store IPv4 in IPv6-mapped form) with value {u64 bytes, u64 pkts}
  - Flow counters (optional): `BPF_MAP_TYPE_LRU_HASH` with a compact 5-tuple key (proto + src/dst + ports)
  - Control map: `BPF_MAP_TYPE_ARRAY` or `BPF_MAP_TYPE_HASH` for runtime config (sampling rate, enable/disable)
- Pin path: `/sys/fs/bpf/traffic_counter/<map-name>` to allow userspace to open maps after reload.

## Map schema (C-like pseudocode)

```c
struct ip_key {
  __u8 family; // AF_INET(2) or AF_INET6(10)
  __u8 pad[7];
  __u64 addr_lo; // for IPv4 store in low bits; IPv6 uses addr_lo/addr_hi
  __u64 addr_hi;
};

struct counters {
  __u64 bytes;
  __u64 packets;
};

// Example map declarations (user-visible names)
// per-cpu hash: "traffic_counters_ip"
// lru hash for flows: "traffic_counters_flow"
```

## Fast-path behavior

- Parse L2/L3/L4 headers reliably and cheaply. For malformed packets, increment a `dropped` counter in the control map.
- Look up the per-CPU counter by IP key and perform atomic addition of packet length and +1 packet count.

## Userspace model

- Userspace uses `aya` to open pinned maps, iterate keys, sum per-CPU counters, and export metrics.
- Provide a mode to periodically snapshot and optionally clear counters (configurable). Clearing requires care with per-CPU maps—use map delete or reset semantics.

## Resource and safety considerations

- Map sizes: document defaults (e.g., 65_536 entries for IP map, adjustable via build-time or runtime config). Default LRU for flow map to avoid unbounded growth.
- eBPF stack limits: avoid stack-heavy parsing; use bounded loops only.
- Use `bpf_probe_read` / helpers that are allowed in the chosen attach point.

## Testing

- Unit test of userspace aggregation logic.
- Integration test: load compiled object in a privileged VM, generate traffic, verify counts.
