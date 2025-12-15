# Tasks

## 1) Implementation

- [x] Implement AF_PACKET capture path with fanout and copy-less ring buffers
- [x] Build and attach eBPF/classic BPF filter program for frame pre-selection
- [x] Update CLI/runtime to toggle packet-socket mode, configure fanout group, and expose stats

## 2) Testing & docs

- [ ] Add integration tests (or smoke scripts) covering packet capture and counting correctness
- [ ] Document operational steps, limits, and migration guidance in README + spec updates
- [ ] Ensure `openspec` specs stay in sync after implementation
