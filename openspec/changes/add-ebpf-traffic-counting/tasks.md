# Tasks for implementation

## 1) Scaffolding & build

## 2) eBPF implementation

- [ ] Implement XDP program that parses the packet headers and updates per-IP counters
- [ ] Add optional `tc` or socket filter variant if XDP is incompatible with target workloads
- [ ] Add map definitions: per-CPU counters, LRU map for flow keys (optional), control map for config

## 3) Userspace integration

- [ ] Extend loader to pin maps and load programs using `aya`
- [ ] Add reader that aggregates per-CPU counters into totals and exposes metrics (Prometheus/HTTP)
- [ ] Add CLI/config to choose eBPF attach point (XDP vs TC) and map sizes

## 4) Testing & CI

- [ ] Unit tests for reader/aggregator logic

## 5) Docs & rollout

- [ ] Document map schemas and pin locations in `openspec/project.md`
- [ ] Create migration plan for future map schema changes
- [ ] Add README usage and troubleshooting notes
