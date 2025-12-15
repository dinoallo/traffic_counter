#![no_std]

// Common types shared between userspace and eBPF programs.
// Keep this crate `no_std` friendly so it can be used from eBPF code.

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct IpKey {
    pub family: u8,
    pub pad: [u8; 7],
    pub addr_lo: u64,
    pub addr_hi: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Counters {
    pub bytes: u64,
    pub packets: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct FlowKey {
    pub family: u8,
    pub proto: u8,
    pub pad0: [u8; 2],
    pub src_port: u16,
    pub dst_port: u16,
    pub pad1: u32,
    pub src_addr_lo: u64,
    pub src_addr_hi: u64,
    pub dst_addr_lo: u64,
    pub dst_addr_hi: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlConfig {
    pub enable_flow_counters: u8,
    pub reserved: [u8; 7],
    pub ip_map_capacity: u32,
    pub flow_map_capacity: u32,
    pub dropped_packets: u64,
}

// When compiled for userspace with the `user` feature enabled the crate
// exposes an implementation of `aya::Pod` for these types so they can be
// used with aya's typed map APIs. We keep this behind a feature so the
// no_std eBPF side doesn't pull in userspace-only dependencies.
#[cfg(feature = "user")]
mod user_impls {
    extern crate aya;

    use super::{ControlConfig, Counters, FlowKey, IpKey};
    use aya::Pod;

    unsafe impl Pod for IpKey {}
    unsafe impl Pod for Counters {}
    unsafe impl Pod for FlowKey {}
    unsafe impl Pod for ControlConfig {}
}
