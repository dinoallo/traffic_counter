use std::fmt::Display;
use std::net::IpAddr;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct HttpMeta {
    pub host_ip: String,
    pub client_ip: String,
    pub host: String,
}

impl Display for HttpMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host_ip: {} client_ip: {} host: {}",
            self.host_ip, self.client_ip, self.host
        )
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct L4Meta {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

impl Default for L4Meta {
    fn default() -> Self {
        Self {
            local_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            remote_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            local_port: 0,
            remote_port: 0,
            protocol: 0,
        }
    }
}

impl std::fmt::Display for L4Meta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} proto:{}",
            self.local_ip, self.local_port, self.remote_ip, self.remote_port, self.protocol
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct SvcMeta {
    pub namespace: String,
    pub service_name: String,
}

impl std::fmt::Display for SvcMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.service_name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PodMeta {
    pub namespace: String,
    pub pod_name: String,
}

impl std::fmt::Display for PodMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.pod_name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct K8sIngressTraffic {
    pub http_meta: HttpMeta,
    pub svc_meta: SvcMeta,
    pub request_bytes: u64,
    pub response_bytes: u64,
}

impl std::fmt::Display for K8sIngressTraffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "http_meta: [{}] svc_meta: [{}] request_bytes: {} response_bytes: {}",
            self.http_meta, self.svc_meta, self.request_bytes, self.response_bytes
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct K8sNodePortTraffic {
    pub l4_meta: L4Meta,
    pub svc_meta: SvcMeta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl std::fmt::Display for K8sNodePortTraffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "l4_meta: [{}] svc_meta: [{}] rx_bytes: {} rx_packets: {} tx_bytes: {} tx_packets: {}",
            self.l4_meta,
            self.svc_meta,
            self.rx_bytes,
            self.rx_packets,
            self.tx_bytes,
            self.tx_packets
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct K8sPodToWorldTraffic {
    pub l4_meta: L4Meta,
    pub pod_meta: PodMeta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl std::fmt::Display for K8sPodToWorldTraffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "l4_meta: [{}] pod_meta: [{}] rx_bytes: {} rx_packets: {} tx_bytes: {} tx_packets: {}",
            self.l4_meta,
            self.pod_meta,
            self.rx_bytes,
            self.rx_packets,
            self.tx_bytes,
            self.tx_packets
        )
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct L4Traffic {
    pub l4_meta: L4Meta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl std::fmt::Display for L4Traffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "l4_meta: [{}] rx_bytes: {} rx_packets: {} tx_bytes: {} tx_packets: {}",
            self.l4_meta, self.rx_bytes, self.rx_packets, self.tx_bytes, self.tx_packets
        )
    }
}

#[derive(Debug, Clone)]
pub enum Traffic {
    K8sIngress(K8sIngressTraffic),
    K8sNodePort(K8sNodePortTraffic),
    K8sPodToWorld(K8sPodToWorldTraffic),
    L4(L4Traffic),
    Unknown,
}

impl std::fmt::Display for Traffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Traffic::K8sIngress(t) => write!(f, "K8sIngress Traffic: [{}]", t),
            Traffic::K8sNodePort(t) => write!(f, "K8sNodePort Traffic: [{}]", t),
            Traffic::K8sPodToWorld(t) => write!(f, "K8sPodToWorld Traffic: [{}]", t),
            Traffic::L4(t) => write!(f, "L4 Traffic: [{}]", t),
            Traffic::Unknown => write!(f, "Unknown Traffic"),
        }
    }
}

pub trait Aggregatable {
    fn aggregate(&mut self, other: &Self);
}

impl Aggregatable for L4Traffic {
    fn aggregate(&mut self, other: &Self) {
        self.rx_bytes += other.rx_bytes;
        self.rx_packets += other.rx_packets;
        self.tx_bytes += other.tx_bytes;
        self.tx_packets += other.tx_packets;
    }
}

impl Aggregatable for K8sNodePortTraffic {
    fn aggregate(&mut self, other: &Self) {
        self.rx_bytes += other.rx_bytes;
        self.rx_packets += other.rx_packets;
        self.tx_bytes += other.tx_bytes;
        self.tx_packets += other.tx_packets;
    }
}

impl Aggregatable for K8sIngressTraffic {
    fn aggregate(&mut self, other: &Self) {
        self.request_bytes += other.request_bytes;
        self.response_bytes += other.response_bytes;
    }
}

impl Aggregatable for K8sPodToWorldTraffic {
    fn aggregate(&mut self, other: &Self) {
        self.rx_bytes += other.rx_bytes;
        self.rx_packets += other.rx_packets;
        self.tx_bytes += other.tx_bytes;
        self.tx_packets += other.tx_packets;
    }
}

impl Aggregatable for Traffic {
    fn aggregate(&mut self, other: &Self) {
        match (self, other) {
            (Traffic::K8sIngress(existing), Traffic::K8sIngress(new)) => {
                existing.aggregate(new);
            }
            (Traffic::K8sNodePort(existing), Traffic::K8sNodePort(new)) => {
                existing.aggregate(new);
            }
            (Traffic::K8sPodToWorld(existing), Traffic::K8sPodToWorld(new)) => {
                existing.aggregate(new);
            }
            (Traffic::L4(existing), Traffic::L4(new)) => {
                existing.aggregate(new);
            }
            _ => {}
        }
    }
}
