use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct HttpMeta {
    pub host_ip: String,
    pub client_ip: String,
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct K8sIngressTraffic {
    pub http_meta: HttpMeta,
    pub svc_meta: SvcMeta,
    pub request_bytes: u64,
    pub response_bytes: u64,
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

#[derive(Debug, Clone)]
pub struct SvcMeta {
    pub namespace: String,
    pub service_name: String,
}

#[derive(Debug, Clone)]
pub struct K8sNodePortTraffic {
    pub l4_meta: L4Meta,
    pub svc_meta: SvcMeta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone)]
pub struct PodMeta {
    pub namespace: String,
    pub pod_name: String,
}

#[derive(Debug, Clone)]
pub struct K8sPodToWorldTraffic {
    pub l4_meta: L4Meta,
    pub pod_meta: PodMeta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone)]
pub enum K8sTraffic {
    K8sIngress(K8sIngressTraffic),
    K8sNodePort(K8sNodePortTraffic),
    K8sPodToWorld(K8sPodToWorldTraffic),
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
            "rx_bytes: {} rx_packets: {} tx_bytes: {} tx_packets: {}",
            self.rx_bytes, self.rx_packets, self.tx_bytes, self.tx_packets
        )
    }
}

#[derive(Debug, Clone)]
pub enum Traffic {
    K8s(K8sTraffic),
    L4(L4Traffic),
    Unknown,
}
