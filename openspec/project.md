# Traffic Counter

## Purpose

This project attaches to devices on the node, and count the traffic from/to IP addresses.

## Tech Stack

- **Language:** Rust (2024 edition)
- **eBPF framework:** `aya` for writing & loading eBPF programs from userspace
- **Async runtime:** `tokio` (userspace agent components)
- **Logging / observability:** `tracing`, `tracing-subscriber`
- **Error handling:** `anyhow` / `thiserror` for structured error types in userspace
- **Build tools (native):** `clang` / `llvm` (for compiling eBPF C/LLVM IR when applicable), `bpftool` for inspection

Notes: keep crate versions up-to-date in `Cargo.toml`; pin a tested `aya` minor version and bump deliberately.

## Project Conventions

### Code Style

- **Formatting:** Run `cargo fmt` (Rust `rustfmt`) before committing. The repository targets the Rust 2024 edition.
- **Lints:** Enable `clippy` in CI and treat important lints as errors locally (`cargo clippy -- -D warnings`) for the userspace code. For eBPF programs follow `aya` guidance — use eBPF-friendly patterns and avoid unsupported std APIs.
- **Naming:** Use `snake_case` for functions and variables, `CamelCase` for types. Place eBPF programs in `src/bpf` or `ebpf/` and userspace agent code in `src/`.
- **Docs & comments:** Public functions and complex modules should have doc comments. Small helpers can use inline comments sparingly.

### Architecture Patterns

- **Separation of concerns:** Keep eBPF programs (kernel code) and userspace controller code strictly separated. eBPF code must be minimal and deterministic; userspace handles aggregation, exporting, and control.
- **eBPF maps:** Use clearly named maps and pin them under `/sys/fs/bpf/<project>/` when long-lived state is needed. Keep map layouts stable between versions and document schema changes.
- **Controller model:** Userspace agent loads eBPF bytecode, attaches programs (XDP/tc/kprobe as appropriate), and polls or receives events (perf buffers) to build aggregates.
- **Data model:** Primary unit is a per-IP traffic counter (bytes/packets) with optional 5-tuple flow keys for future extension.
- **Export:** Expose metrics via a small HTTP endpoint or push metrics to Prometheus via an exporter component (recommended separate crate or binary).

### Testing Strategy

- **Unit tests:** Keep pure-Rust logic covered by `cargo test` (userspace components). Aim for high coverage on parsers, aggregators, and exporters.
- **Integration tests:** Add integration tests that exercise the userspace controller logic (mocked eBPF maps or in-process simulation). Use `#[cfg(test)]` integration harnesses.
- **End-to-end:** E2E tests that load the eBPF program and run traffic generation should be run manually or in a privileged CI runner (VM) because they require root and kernel capabilities.
- **CI policy:** Run `cargo fmt -- --check`, `cargo clippy -- -D warnings`, and `cargo test` on every PR. If possible, include a job that runs a smoke E2E test inside a VM/container with elevated privileges.

### Git Workflow

- **Branching:** Use feature branches named `feat/<short-desc>` and fix branches `fix/<short-desc>`. Long-lived branches should be avoided.
- **Commits:** Keep commits small and focused. Use imperative present tense in commit messages (e.g., "Add X", "Fix Y").
- **Pull requests:** Require at least one reviewer and passing CI checks before merge. Use descriptive PR titles and a short summary.
- **Releases:** Tag releases with semantic versioning (vMAJOR.MINOR.PATCH). Document breaking changes in the changelog.
- **Code owner:** Add CODEOWNERS if there's a stable maintainer set for eBPF parts vs userspace parts.

## Domain Context

This project is a lightweight traffic counter that attaches to network-facing points on a node and captures network traffic counts keyed by IP address (and optionally by flow key). It is intended for:

- short-term per-node visibility of traffic volumes
- exporting metrics to monitoring systems (Prometheus)
- acting as a data source for higher-level network analysis or alerts

Design implications:

- Keep eBPF logic minimal — counting/observability only. Any heavy aggregation or enrichment happens in userspace.
- Keys must be compact (IP or 5-tuple) to keep eBPF map memory usage predictable.

## Important Constraints

- **Platform:** Linux only. Kernel version should be >= 5.4 for broader eBPF feature support, but prefer testing on the minimum kernel you intend to support.
- **Privileges:** Loading and attaching eBPF programs requires elevated privileges (CAP_BPF, CAP_NET_ADMIN) or root.
- **eBPF limits:** eBPF programs have limited stack and no heap allocation — keep programs small and map-driven.
- **Performance:** Be mindful of map sizes and update rates; use per-CPU maps where appropriate and avoid heavy work in fast paths (XDP).
- **Compatibility:** Keep map and perf buffer schemas stable across releases or provide migration tooling for pinned maps.

## External Dependencies

- `aya` — primary eBPF framework for building and loading programs (Rust-first approach).
- `tokio` — async runtime for the userspace agent.
- `tracing`, `tracing-subscriber` — structured logging and diagnostics.
- `anyhow`, `thiserror` — ergonomic error handling.
- Native tools: `clang`, `llvm`, `bpftool`, and kernel headers for building and inspecting eBPF artifacts.

Install notes: developers should have `rustup`, `cargo`, `clang`, `llvm`, and `bpftool` installed. Running the binary on a host requires appropriate capabilities or root.

Build helpers

- A `Makefile` is provided at the repository root for common developer tasks: `make build` (userspace), `make build-ebpf` (compile eBPF C files), `make fmt`, `make clippy`, `make test`, and `make clean`.
- Helper scripts live in `scripts/`:
  - `scripts/build-ebpf.sh` — compiles all `*.c` files from `ebpf/` into `target/bpf/` using `clang -target bpf`.
  - `scripts/check-deps.sh` — verifies `cargo`, `rustc`, `clang`, and `bpftool` are available on the PATH.

Usage examples:

```bash
# Build userspace and eBPF objects
make build
make build-ebpf

# Check required host tools
make check-ebpf
```
