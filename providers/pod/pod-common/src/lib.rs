#![no_std]

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct Event {
    pub len: u32,
    pub protocol: u32,
    pub family: u32,
    pub local_ipv4: u32,
    pub local_ipv6: [u32; 4],
    pub remote_ipv4: u32,
    pub remote_ipv6: [u32; 4],
    pub local_port: u32,
    pub remote_port: u32,
    pub direction: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum Direction {
    Ingress,
    Egress,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
pub const PROGRAM_NAME_PREFIX: &str = "count_traffic_";
