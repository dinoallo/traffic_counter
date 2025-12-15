# traffic Specification

## Purpose

TBD - created by archiving change add-ebpf-traffic-counting. Update Purpose after archive.

## Requirements

### Requirement: Kernel-side per-IP traffic counting

The system SHALL maintain per-IP traffic counters in the kernel using eBPF programs. Counters SHALL record total bytes and total packets for each observed IP address.

#### Scenario: Basic counting (IPv4)

- **WHEN** the eBPF program is attached and traffic is sent between two IPv4 hosts
- **THEN** the kernel-side per-IP counter for the destination and source addresses SHALL be incremented by the packet length and by one packet

#### Scenario: IPv6 support

- **WHEN** traffic includes IPv6 addresses
- **THEN** the system SHALL record counters for IPv6 keys (supporting full 128-bit addresses)

#### Scenario: Map pinning and persistence

- **WHEN** userspace loads and pins maps at `/sys/fs/bpf/traffic_counter/`
- **THEN** userspace SHALL be able to open pinned maps across process restarts and aggregate counters without losing pinned map state

#### Scenario: Resource limits

- **WHEN** map capacity is exceeded (e.g., too many distinct IP keys)
- **THEN** the system SHALL either drop new distinct keys (for fixed-size hash maps) or evict least-recently-used entries (for LRU maps), and expose a metric for `map_evictions` or `map_capacity_exceeded`

### Requirement: Userspace aggregation and export

Userspace SHALL be able to read per-CPU counters from kernel maps, aggregate them safely into a global count, and expose metrics via an HTTP endpoint or Prometheus exporter.

#### Scenario: Aggregation correctness

- **WHEN** userspace reads per-CPU map values concurrently with kernel updates
- **THEN** the aggregation logic SHALL sum per-CPU counters and produce correct totals for the reporting period (within expected concurrency semantics)

### Requirement: Safety and resource constraints

eBPF programs SHALL avoid unbounded loops and heavy per-packet work. The project SHALL document recommended map sizes and attach-point tradeoffs.

#### Scenario: Malformed packets

- **WHEN** the eBPF parser encounters a malformed or truncated packet
- **THEN** the program SHALL increment a `parsing_errors` metric and avoid crashing or violating verifier constraints
