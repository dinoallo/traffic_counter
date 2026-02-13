# Change: Attach eBPF programs inside pod network namespaces

## Why
We need to ensure traffic counting applies inside each pod’s network namespace by attaching programs to `eth0` within those namespaces, not just the host namespace.

## What Changes
- Discover all pod network namespaces on the host.
- For each namespace, attach our eBPF programs to `eth0` when present.
- Ensure we safely skip namespaces without `eth0` and handle transient namespaces.

## Impact
- Affected specs: `traffic`
- Affected code: pod provider userspace runtime, namespace discovery/attachment logic