## 1. Implementation

- [x] Review existing pod provider attachment flow and identify integration points for netns traversal.
- [x] Implement pod network namespace discovery on the host.
- [x] For each namespace, enter netns and detect `eth0`.
- [x] Attach ingress and egress programs to `eth0` when present.
- [x] Skip namespaces without `eth0` and handle transient namespace errors gracefully.
- [x] Add structured logging for namespace discovery, attach success, and attach failures.

## 2. Validation

- [x] Add basic unit tests for namespace discovery helpers (mockable where possible).
- [x] Document manual verification steps for privileged testing in a real cluster.
- [ ] Run `cargo fmt` and `cargo clippy -- -D warnings` for userspace crates.

## 3. Documentation

- [x] Update relevant README or operator docs to describe netns-based attachments.
- [x] Add notes on required privileges and expected attach points.