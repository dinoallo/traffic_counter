# Change: Refactor traffic counting using packet(7) sockets

## Why

- Some CNIs, such as Cilium, attach their BPF programs to the traffic control (TC) side. These programs may not delegate packets to the counter's program. Consequently, the counter either (a) does not receive the packets, or (b) does not receive the masqueraded/revDNATed packets.
- Moving per-IP accounting into userspace simplifies upgrades and avoids pinned map lifecycle issues.

## What Changes

- Introduce a packet(7) capture path that joins RX queues via `PACKET_FANOUT`, runs an attached eBPF filter to drop irrelevant traffic, and forwards accepted frames to a userspace counter pipeline.
- Replace the current kernel-resident per-IP counter maps with a userspace hashmap fed from packet socket frames; maintain feature parity for IPv4/IPv6 plus optional flow keys.
- Update the CLI/runtime so operators can select AF_PACKET ingestion, tune fanout/queue sizing, and monitor packet/byte counters plus drop statistics.
- Document operational guidance (capabilities, required capabilities, permissions) for the packet-socket mode.

## Impact

- Affected specs: `traffic`
- Affected code: `traffic-counter-ebpf` (filter program), `traffic-counter` userspace runtime/CLI, docs in `README.md` and `openspec/project.md`
- Operationally removes reliance on pinned BPF maps, introduces dependency on packet socket fanout groups, and requires auditing of permissions (CAP_NET_RAW + CAP_BPF).
