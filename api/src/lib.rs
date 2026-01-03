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
pub struct HttpGatewayTraffic {
    pub http_meta: HttpMeta,
    pub request_bytes: u64,
    pub response_bytes: u64,
}

impl std::fmt::Display for HttpGatewayTraffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "http_meta: [{}] request_bytes: {} response_bytes: {}",
            self.http_meta, self.request_bytes, self.response_bytes
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodePortTraffic {
    pub l4_meta: L4Meta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl std::fmt::Display for NodePortTraffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "l4_meta: [{}] rx_bytes: {} rx_packets: {} tx_bytes: {} tx_packets: {}",
            self.l4_meta, self.rx_bytes, self.rx_packets, self.tx_bytes, self.tx_packets
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClusterTraffic {
    pub l4_meta: L4Meta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl std::fmt::Display for ClusterTraffic {
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
    NodePort(NodePortTraffic),
    HttpGateway(HttpGatewayTraffic),
    Cluster(ClusterTraffic),
}

impl std::fmt::Display for Traffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Traffic::NodePort(t) => write!(f, "NodePort Traffic: [{}]", t),
            Traffic::HttpGateway(t) => write!(f, "HttpGateway Traffic: [{}]", t),
            Traffic::Cluster(t) => write!(f, "Cluster Traffic: [{}]", t),
        }
    }
}
pub trait Aggregatable {
    fn aggregate(&mut self, other: &Self);
}

impl Aggregatable for NodePortTraffic {
    fn aggregate(&mut self, other: &Self) {
        self.rx_bytes += other.rx_bytes;
        self.rx_packets += other.rx_packets;
        self.tx_bytes += other.tx_bytes;
        self.tx_packets += other.tx_packets;
    }
}

impl Aggregatable for HttpGatewayTraffic {
    fn aggregate(&mut self, other: &Self) {
        self.request_bytes += other.request_bytes;
        self.response_bytes += other.response_bytes;
    }
}

impl Aggregatable for ClusterTraffic {
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
            (Traffic::NodePort(existing), Traffic::NodePort(new)) => existing.aggregate(new),
            (Traffic::HttpGateway(existing), Traffic::HttpGateway(new)) => existing.aggregate(new),
            (Traffic::Cluster(existing), Traffic::Cluster(new)) => existing.aggregate(new),
            _ => {}
        }
    }
}
