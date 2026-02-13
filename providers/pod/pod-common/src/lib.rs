#![no_std]

#[derive(Copy, Clone)]
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
}
impl Default for Event {
    fn default() -> Self {
        Self {
            len: 0,
            protocol: 0,
            family: 0,
            local_ipv4: 0,
            local_ipv6: [0; 4],
            remote_ipv4: 0,
            remote_ipv6: [0; 4],
            local_port: 0,
            remote_port: 0,
        }
    }
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
