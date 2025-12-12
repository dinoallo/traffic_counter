# Tasks for implementation

## 1) Scaffolding & build

- [x] Add initial scaffolding: map schema doc and userspace loader stub

## 2) eBPF implementation

- [x] Implement XDP program that parses the packet headers and updates per-IP counters
  - Implemented `xdp_traffic_counter` in `traffic-counter-ebpf/src/main.rs`, including IPv4/IPv6 parsing and per-CPU counter updates keyed by `IpKey`.
- [x] Add optional `tc` or socket filter variant if XDP is incompatible with target workloads
  - Added `tc_traffic_counter` (Aya `#[classifier]`) in `traffic-counter-ebpf/src/main.rs`, sharing the same parsing/counter logic as the XDP program so environments without XDP can attach via `tc`.
- [x] Add map definitions: per-CPU counters, LRU map for flow keys (optional), control map for config

## 3) Userspace integration

- [x] Extend loader to pin maps and load programs using `aya`
- [x] Add reader that aggregates per-CPU counters into totals (CLI)
  - Note: a CLI reader (`aggregate_per_cpu_counters`) is implemented that opens a pinned per-CPU hash map via `aya`, aggregates per-CPU `Counters` into totals and returns JSON. Prometheus/HTTP exporter is still TODO.
- [x] Add CLI/config to choose eBPF attach point (XDP vs TC) and map sizes

## 4) Testing & CI

- [x] Unit tests for reader/aggregator logic

## 5) Docs & rollout

- [x] Document map schemas and pin locations in `openspec/project.md`
- [x] Create migration plan for future map schema changes
- [x] Add README usage and troubleshooting notes
