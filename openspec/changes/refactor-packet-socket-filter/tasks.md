# Tasks

## 1) Planning & design

- [ ] Review packet(7) requirements (fanout, tpacket v3) and finalize design.md
- [ ] Validate capability/security constraints (CAP_NET_RAW, CAP_BPF or classic BPF fallback)

## 2) Implementation

- [x] Implement AF_PACKET capture path with fanout and copy-less ring buffers
- [x] Build and attach eBPF/classic BPF filter program for frame pre-selection
- [ ] Move per-IP/per-flow counting logic into userspace data structures (with sharding to avoid contention)
- [x] Update CLI/runtime to toggle packet-socket mode, configure fanout group, and expose stats
- [ ] Remove/preserve legacy XDP/TC attach path behind a feature flag or migration switch

## 3) Testing & docs

- [ ] Add integration tests (or smoke scripts) covering packet capture and counting correctness
- [ ] Document operational steps, limits, and migration guidance in README + spec updates
- [ ] Ensure `openspec` specs stay in sync after implementation
