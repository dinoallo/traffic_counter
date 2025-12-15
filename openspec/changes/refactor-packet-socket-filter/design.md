# Refactor to packet(7) capture path

## Context

The current system attaches eBPF programs (XDP or tc clsact) that increment per-IP counters inside kernel maps. In multi-tenant clusters, CNIs such as Cilium already occupy the tc ingress/egress hooks and delegate to third-party programs, meaning our counter might not handle packets correctly.  leveraging packet(7) sockets with an attached filter shrinks kernel requirements and lets us move aggregation into Rust userspace code while bypassing CNI tc chains entirely.

## Goals

- Provide an AF_PACKET-based ingestion path that scales across RX queues using `PACKET_FANOUT`.
- Keep IPv4/IPv6 per-IP and optional per-flow counters feature-complete with the previous kernel-map design.
- Offer run-time configuration for fanout mode, ring buffer sizing, and CPU pinning.
- Maintain a narrow eBPF filter that just enforces drop rules (e.g., ignore non-IP, optional VLAN filtering).
- Replace every existing attach point immediately

## Non-Goals

- Building a full PCAP recorder—only counting is in scope.

## Decisions

1. **Ingestion mechanism**: Use `AF_PACKET` + `SO_ATTACH_BPF` (classic or eBPF) filter. Each instance joins a configurable fanout group to spread load across worker threads.
2. **Counting location**: Userspace maintains `DashMap`/sharded hash maps keyed by `IpKey` and optional `FlowKey`. Periodic snapshots feed exporters.
3. **Filter content**: Filter ensures only L3 IPv4/IPv6 packets reach userspace and may respect control-plane allowlists. Filter code remains in `traffic-counter-ebpf` but compiled for socket filter type.
4. **Backpressure handling**: Configure TPACKET_V3 ring buffers sized off NIC speed; expose stats for dropped frames due to ring overruns and filter rejects.
5. **Security/perms**: Document requirement for `CAP_NET_RAW` and (if eBPF filter is used) `CAP_BPF` or `CAP_SYS_ADMIN` depending on kernel. Provide fallback to classic BPF bytecode for older kernels.

## Risks / Trade-offs

- Userspace counting adds CPU overhead; mitigated by sharded locks and optional SIMD aggregation.
- Packet sockets can drop traffic under sustained bursts; mitigation via larger ring buffers and telemetry for overruns.
- Introducing a second ingest path complicates CLI/configuration; solved via clear defaults and mutual exclusion flags.

## Open Questions

- Do we need an additional perf buffer or channel to surface filter-drop stats in real time?
