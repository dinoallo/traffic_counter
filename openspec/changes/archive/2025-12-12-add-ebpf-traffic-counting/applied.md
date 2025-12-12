# Applied: add-ebpf-traffic-counting

This change now has a functional kernel + userspace slice wired up:

- Implemented the `xdp_traffic_counter` program in `traffic-counter-ebpf/src/main.rs`. It parses Ethernet + IPv4/IPv6 headers, constructs an `IpKey`, and updates a pinned `PerCpuHashMap` (`traffic_counters_ip`) with per-packet byte/packet deltas.
- Added a `tc_traffic_counter` fallback (Aya `#[classifier]`) that reuses the same parsing/counter helpers, allowing deployments that cannot run XDP to attach via `tc` while keeping identical map outputs.
- Added the `traffic-counter-common` crate that houses the shared `IpKey`/`Counters` structs; it remains `no_std` for eBPF but exposes `aya::Pod` impls via the `user` feature so typed maps work in userspace.
- Replaced the userspace stub with a working aya-only reader (`traffic-counter/src/ebpf_loader.rs`) plus a `dump-maps` CLI subcommand (`traffic-counter/src/main.rs`). The loader opens a pinned per-CPU hash map via `MapData::from_pin` → `Map::from_map_data` → `PerCpuHashMap::try_from`, aggregates all CPUs, and prints JSON totals.
- Verified `cargo build -p traffic-counter` to ensure the new loader and shared crate compile cleanly.

Next steps:

- Add the optional `tc`/socket-filter variant and additional map schemas (flow LRU/control maps) per the design.
- Extend userspace with Prometheus/HTTP export plus attach-point/config plumbing, then add tests/CI jobs before rolling out docs + migrations.

Applied-by: automated OpenSpec assistant
Date: 2025-12-11
