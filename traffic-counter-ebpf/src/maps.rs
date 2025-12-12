// Map schema and key/value definitions for eBPF programs.
// This file documents the intended map layouts and provides
// copy/paste-ready pseudocode for C/Rust-BPF implementations.

#![no_std]

// NOTE: This file is documentation-first. Implementations for aya-bpf
// (Rust) or C should mirror these layouts in the actual eBPF source.

// C-like pseudocode for keys and values:
/*
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

// Example map names (user-visible):
// - per-cpu hash (preferred for counters): "traffic_counters_ip"
// - lru hash for flows: "traffic_counters_flow"
// - control/config: "traffic_control"
*/

// Suggested defaults (documented only):
// - ip map entries: 65_536
// - flow map entries: 16_384 (LRU)
// - control map: small array (size 8)
