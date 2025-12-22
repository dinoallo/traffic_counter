use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context, Result, anyhow};
pub struct AddressList {
    ipv4: Vec<Ipv4Net>,
    ipv6: Vec<Ipv6Net>,
}

struct Ipv4Net {
    network: u32,
    mask: u32,
}

struct Ipv6Net {
    network: u128,
    mask: u128,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Flow {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} proto:{}",
            self.local_ip, self.local_port, self.remote_ip, self.remote_port, self.protocol
        )
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Counter {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl std::fmt::Display for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rx_bytes: {} rx_packets: {} tx_bytes: {} tx_packets: {}",
            self.rx_bytes, self.rx_packets, self.tx_bytes, self.tx_packets
        )
    }
}

impl AddressList {
    pub fn empty() -> Self {
        Self {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        }
    }

    pub fn from_option(path: Option<&Path>, label: &str) -> Result<Self> {
        match path {
            Some(path) => Self::from_path(path, label),
            None => Ok(Self::empty()),
        }
    }

    fn from_path(path: &Path, label: &str) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open {label} at {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!(
                    "failed to read line {} of {} ({label})",
                    line_no + 1,
                    path.display()
                )
            })?;
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let (addr_part, prefix_part) = trimmed.split_once('/').ok_or_else(|| {
                anyhow!(
                    "line {} of {} ({label}) must be CIDR notation (addr/prefix)",
                    line_no + 1,
                    path.display()
                )
            })?;
            let addr: IpAddr = addr_part.trim().parse().with_context(|| {
                format!(
                    "invalid IP address '{}' on line {} of {} ({label})",
                    addr_part.trim(),
                    line_no + 1,
                    path.display()
                )
            })?;
            let prefix: u8 = prefix_part.trim().parse().with_context(|| {
                format!(
                    "invalid prefix '{}' on line {} of {} ({label})",
                    prefix_part.trim(),
                    line_no + 1,
                    path.display()
                )
            })?;
            match addr {
                IpAddr::V4(addr) => {
                    if prefix > 32 {
                        return Err(anyhow!(
                            "prefix {} exceeds IPv4 width on line {} of {} ({label})",
                            prefix,
                            line_no + 1,
                            path.display()
                        ));
                    }
                    let mask = ipv4_mask(prefix);
                    let network = u32::from_be_bytes(addr.octets()) & mask;
                    ipv4.push(Ipv4Net { network, mask });
                }
                IpAddr::V6(addr) => {
                    if prefix > 128 {
                        return Err(anyhow!(
                            "prefix {} exceeds IPv6 width on line {} of {} ({label})",
                            prefix,
                            line_no + 1,
                            path.display()
                        ));
                    }
                    let mask = ipv6_mask(prefix);
                    let network = ipv6_to_u128(addr) & mask;
                    ipv6.push(Ipv6Net { network, mask });
                }
            }
        }

        Ok(Self { ipv4, ipv6 })
    }

    pub fn contains(&self, key: &IpAddr) -> bool {
        match key {
            IpAddr::V4(addr) => {
                let value = u32::from_be_bytes(addr.octets());
                self.ipv4
                    .iter()
                    .any(|net| (value & net.mask) == net.network)
            }
            IpAddr::V6(addr) => {
                let value = ipv6_to_u128(*addr);
                self.ipv6
                    .iter()
                    .any(|net| (value & net.mask) == net.network)
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

fn ipv6_to_u128(addr: Ipv6Addr) -> u128 {
    u128::from_be_bytes(addr.octets())
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}
