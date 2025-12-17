# Traffic Counter

Traffic Counter is a per-node network traffic counting agent that combines a small eBPF socket filter with a userspace AF_PACKET pipeline to record per-IP (and optionally per-flow) byte and packet counters. The userspace portion is written in Rust, with shared types captured in `traffic-counter-common` and a dedicated filter crate in `traffic-counter-ebpf`.

**This project targets Linux hosts and requires kernel eBPF support and elevated privileges to load programs.**

> **Active development:** This project changes quickly and may introduce breaking updates between releases. Check `openspec/` for the latest specs and roadmap details before building on top of current interfaces.

## Status: packet-socket ingestion

The `refactor-packet-socket-filter` change now captures traffic exclusively through an `AF_PACKET` pipeline. Each node process:

- Joins interface RX queues via `PACKET_FANOUT` and TPACKET_V3 rings.
- Loads the socket filter from `traffic-counter-ebpf` to drop non-IP frames before userspace work.
- Counts per-IP (and optional per-flow) stats inside sharded hash maps and publishes deltas at a fixed cadence.

Review the detailed design in `openspec/changes/refactor-packet-socket-filter/` before extending the agent.

## Quick Start

1. Build the userspace binary (this also embeds the latest socket-filter artifact):

```bash
cargo build --release
```

1. Launch the packet-socket ingestion pipeline. Pick an interface, fanout group, worker count, and ring sizing that match the NIC you are sampling:

```bash
sudo target/release/traffic-counter node \
    --iface eth0 \
    --workers 4 \
    --fanout-group 101 \
    --block-size 262144 \
    --block-count 1024 \
    --frame-size 4096 \
    --report-interval-secs 5
```

   Provide `--ignore-file path/to/cidrs.txt` or `--accept-source-file path/to/cidrs.txt` to tune what the filter forwards. The CLI prints byte, packet, drop, and hashmap growth deltas each reporting interval.

1. Monitor the streamed stats or pipe them into an exporter. Watch for ring overruns or large drop deltas—they indicate that you need more workers, a different fanout group, or a larger ring.

### Permissions

The loader needs `CAP_NET_RAW` to open packet sockets and `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels) to attach the eBPF filter. Grant the binary capabilities if you prefer not to run it as root:

```bash
sudo setcap cap_net_raw,cap_bpf+ep target/release/traffic-counter
```

## Project Structure

For first-time contributors, here's a short description of the repository layout and where to look.

- `traffic-counter/`: Primary userspace binary crate — runtime, CLI, and the AF_PACKET ingestion pipeline with fanout, ring management, and sharded counters (contains `Cargo.toml`, `src/main.rs`).
- `traffic-counter-common/`: Shared library crate with types and helpers used across the project.
- `traffic-counter-ebpf/`: Socket-filter eBPF program and build logic (Rust `aya-bpf`) used with `SO_ATTACH_BPF`. Compiles to the artifacts embedded by the userspace binary.
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
- If you plan to modify the ingestion pipeline, exposed counters, or control-plane surface area, open a proposal under `openspec/changes/` describing the change.

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

Notes:

- The Rust eBPF crate builds for the `bpfel-unknown-none` target; ensure that target is installed.
- Build artifacts are placed in `target/bpf/` by the Makefile so the userspace loader can find them.

## Container image

Build a containerized version of the collector with the provided multi-stage `Dockerfile`:

```bash
docker build -t traffic-counter:latest .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=BPF \
    traffic-counter:latest node --iface eth0 --workers 4
```

The runtime still needs `CAP_NET_RAW` and `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels) because packet sockets and eBPF filters require those capabilities even inside containers.

## Development notes

- The socket filter must remain short and verifier-friendly; use the Rust `aya-bpf` APIs in `traffic-counter-ebpf/` to describe matches and keep only L3 IP frames.
- Userspace counting happens in sharded hash maps. Tune shard count and worker affinity before optimizing the filter—it is usually the CPU bottleneck.
- Ring sizing matters: set `--block-size`, `--block-count`, and `--frame-size` large enough for the NIC speed to avoid overruns. Stats printed by the CLI call out when the kernel drops frames.

## Testing & CI

- Unit tests and `cargo test` run in CI. The repository includes a GitHub Actions workflow at `.github/workflows/ci.yml` which runs `cargo fmt --check`, `cargo clippy`, `cargo test` and attempts to build the Rust eBPF crate.
- End-to-end testing that loads eBPF programs requires a privileged environment (VM or runner with CAP_BPF / CAP_NET_ADMIN). We recommend doing E2E smoke tests manually or using a dedicated privileged runner.

## Troubleshooting

- Startup errors that mention `EPERM` typically mean the binary lacks `CAP_NET_RAW` or `CAP_BPF`. Either run as root or `setcap cap_net_raw,cap_bpf+ep target/release/traffic-counter`.
- `fanout join failed` indicates that another process already uses your requested `--fanout-group`. Pick a different unsigned 16-bit value or shut down the conflicting process.
- Large drop deltas usually mean the ring is undersized for the traffic profile. Increase `--block-count`, `--block-size`, or `--workers`, and monitor the next report interval.
- If you never see counters for a particular interface, confirm that the NIC exposes an RX queue to packet sockets (`ethtool -S` or `ip link set <iface> up`). Some virtual interfaces block `AF_PACKET` by default.
- Use `sudo bpftool prog show | grep traffic_counter` to verify that the socket filter loaded successfully.

## Contributing

- Follow the code style in `openspec/project.md` (run `cargo fmt` and `cargo clippy`).
- Follow the code style in `openspec/project.md` (run `cargo fmt` and `cargo clippy`). Also lint documentation with `markdownlint` and fix issues before opening a PR.
- Add tests for userspace logic and document any map/schema changes in `openspec/changes/` as an OpenSpec proposal.
