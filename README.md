# Traffic Counter

Traffic Counter is a per-node network traffic counting agent that uses eBPF to record per-IP (and optionally per-flow) byte and packet counters. It includes both a C-based XDP program and a Rust (aya-bpf) implementation, plus a userspace loader built with `aya`.

**This project targets Linux hosts and requires kernel eBPF support and elevated privileges to load programs.**

## Quick Start

1. Build the userspace binary (this also embeds the latest `traffic-counter-ebpf` artifact):

```bash
cargo build --release
```

1. Attach the counter to an interface. Pick the attach point (`xdp`, `tc-ingress`, or `tc-egress`), select an XDP mode when needed, and override map sizes if the defaults are too small:

```bash
sudo target/release/traffic-counter attach \
    --iface eth0 \
    --attach-point xdp \
    --xdp-mode driver \
    --ip-map-size 131072 \
    --enable-flow-map \
    --flow-map-size 65536
```

1. Inspect counters from the pinned maps whenever you need to export or debug totals:

```bash
sudo target/release/traffic-counter dump-maps --pin /sys/fs/bpf/traffic_counter/traffic_counters_ip
```

### Map Pin Layout

All long-lived maps are pinned under `/sys/fs/bpf/traffic_counter/` by default:

- `traffic_counters_ip`: per-CPU hash map keyed by `IpKey` (source IP) that stores `Counters { bytes, packets }`.
- `traffic_counters_flow`: LRU hash map keyed by a 5-tuple style `FlowKey`. It is idle until `--enable-flow-map` is passed.
- `traffic_control`: array map storing runtime flags (`enable_flow_counters`), configured capacities, and drop counters.

You can override any pin path via `--pin`, `--flow-pin`, or `--control-pin` when calling `attach`.

## Project Structure

For first-time contributors, here's a short description of the repository layout and where to look.

- `traffic-counter/`: Primary userspace binary crate — runtime, CLI, and the userspace loader that interacts with eBPF artifacts (contains `Cargo.toml`, `src/main.rs`).
- `traffic-counter-common/`: Shared library crate with types and helpers used across the project.
- `traffic-counter-ebpf/`: eBPF programs and build logic (Rust `aya-bpf` or C helper code). This is the kernel-side code and has its own `build.rs` for producing BPF objects.
- `openspec/`: Design docs, proposals, and project-level specs (including `project.md` and change proposals under `changes/`).
- `scripts/`: Small helper scripts for common developer tasks (`build-ebpf.sh`, `check-deps.sh`).
- Top-level files: `Makefile`, root `Cargo.toml`, and this `README.md` provide build targets, dependency management, and getting-started instructions.
- `target/`: Generated build outputs from `cargo` and native toolchains — not checked into source control.

Where to start:

- Read this `README.md` and `openspec/project.md` to understand conventions and architecture.
- Run dependency checks before building:

```bash
make check-ebpf
```

- Lint Markdown files (install `markdownlint-cli` if needed):

```bash
# install (one-time)
npm install -g markdownlint-cli

# run lint over repository markdown
markdownlint "**/*.md"
```

- Build the userspace binary and eBPF artifacts:

```bash
make build         # build userspace
make build-ebpf    # build eBPF objects (C or Rust targets)
```

- Run unit tests:

```bash
cargo test
```

Notes:

- eBPF development typically requires extra native dependencies and privileged test environments. See the Quick Start and the `scripts/` helpers for developer setup details.
- If you plan to modify map layouts or public interfaces, open a proposal under `openspec/changes/` describing the change.

Prerequisites (developer machine / CI):

- `rustup`, `cargo` (Rust toolchain)
- `clang`, `llvm`, `libelf-dev`, `pkg-config`, `libclang-dev` (for eBPF builds)
- `bpftool` (helpful for inspection)
- `git`, `make`

On Debian/Ubuntu you can install the native deps roughly as:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev pkg-config gcc make libclang-dev bpftool
```

Install Rust toolchain and useful components:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup component add rustfmt clippy
```

To use Aya, you also need the stable and nightly toolchains of Rust:

```bash
rustup install stable
rustup toolchain install nightly --component rust-src
```

Set up the `bpf-linker`:

```bash
cargo install bpf-linker # For linux x86_64 system
LLVM_SYS_180_PREFIX=$(brew --prefix llvm) cargo install \
    --no-default-features bpf-linker # For macos
```

## Build

This repository includes a `Makefile` with convenient targets.

- Build userspace binary:

```bash
make build
# or
cargo build --release
```

- Build C eBPF objects (if you use the C version in `ebpf/`):

```bash
make build-ebpf
```

- Build Rust eBPF crate (`ebpf/rust`) with `aya-bpf` and copy artifact into `target/bpf/`:

```bash
make build-ebpf-rust
```

Notes:

- The Rust eBPF crate builds for the `bpfel-unknown-none` target; ensure that target is installed.
- Build artifacts are placed in `target/bpf/` by the Makefile so the userspace loader can find them.

## Development notes

- eBPF programs must be small and verifier-friendly. Use the Rust `aya-bpf` APIs for stricter type-safety, or maintain the C sources in `traffic-counter-ebpf/` if you need very low-level control.
- Map pinning: BPF maps can be pinned under `/sys/fs/bpf/traffic_counter/` to persist across loader restarts. Userspace will open and aggregate pinned maps when present.
- Aggregation: userspace should sum per-CPU counters to produce global totals before exporting.

## Testing & CI

- Unit tests and `cargo test` run in CI. The repository includes a GitHub Actions workflow at `.github/workflows/ci.yml` which runs `cargo fmt --check`, `cargo clippy`, `cargo test` and attempts to build the Rust eBPF crate.
- End-to-end testing that loads eBPF programs requires a privileged environment (VM or runner with CAP_BPF / CAP_NET_ADMIN). We recommend doing E2E smoke tests manually or using a dedicated privileged runner.

## Troubleshooting

- If attaching the eBPF programs fails, double-check that `/sys/fs/bpf` is mounted and writable, then verify that `traffic_counters_ip`, `traffic_counters_flow`, and `traffic_control` exist (or can be created) under `/sys/fs/bpf/traffic_counter/`.
- Oversized deployments may exhaust the default 65,536-entry IP map or the 32,768-entry flow map. Rerun `traffic-counter attach` with `--ip-map-size` and/or `--flow-map-size` bumped to the desired capacity.
- Flow tracking remains idle until you pass `--enable-flow-map`; the control map reflects the current setting and exposes a `dropped_packets` counter you can inspect with `bpftool map dump`.
- If attaching the ebpf programs fails, verify you have root or the necessary capabilities and that the interface exists.
- Use `sudo bpftool prog show` and `bpftool map show` to inspect loaded programs and maps.

## Contributing

- Follow the code style in `openspec/project.md` (run `cargo fmt` and `cargo clippy`).
- Follow the code style in `openspec/project.md` (run `cargo fmt` and `cargo clippy`). Also lint documentation with `markdownlint` and fix issues before opening a PR.
- Add tests for userspace logic and document any map/schema changes in `openspec/changes/` as an OpenSpec proposal.
