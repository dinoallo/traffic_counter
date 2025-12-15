# Traffic spec delta

## MODIFIED Requirements

### Requirement: Kernel-side per-IP traffic counting

The system SHALL maintain per-IP traffic counters by consuming frames delivered through a packet(7) socket that runs a BPF filter. Counters SHALL continue to track total bytes and packets for each IPv4 or IPv6 address, even though the state now lives in userspace data structures.

#### Scenario: Basic counting (IPv4)

- **WHEN** the packet socket accepts IPv4 traffic destined for the node
- **THEN** the userspace counter pipeline SHALL increment the byte and packet totals for the observed source and destination IPv4 addresses

#### Scenario: IPv6 support

- **WHEN** the filter passes IPv6 frames
- **THEN** the system SHALL encode full 128-bit keys and update the IPv6 counters in the same fashion as IPv4

#### Scenario: Resource limits

- **WHEN** the packet socket ring buffer overflows or the userspace hashmap reaches its configured capacity
- **THEN** the runtime SHALL record drop/overflow metrics so operators can tune ring sizes or shard counts

## ADDED Requirements

### Requirement: Packet socket ingestion pipeline

The system SHALL provide an AF_PACKET ingestion mode that joins RX queues via `PACKET_FANOUT`, attaches a BPF filter to discard irrelevant frames, and streams accepted packets into the counter pipeline.

#### Scenario: Fanout distribution

- **WHEN** multiple worker threads join the same fanout group
- **THEN** traffic SHALL be balanced across workers without duplicate delivery, and the runtime SHALL expose per-worker stats (packets processed, drops)

#### Scenario: Filter enforcement

- **WHEN** the configured packet filter excludes non-IP frames (e.g., ARP, LLDP)
- **THEN** those frames SHALL be dropped in-kernel and counted toward a `filter_drops` metric so operators can confirm policy effectiveness

#### Scenario: Independence from tc programs

- **WHEN** a CNI or other agent attaches tc programs that do not delegate packets to the counter's program
- **THEN** the packet socket ingestion pipeline SHALL continue to see NATed traffic because it receives a copy of packet after thrid-party tc programs finish packet handling.
