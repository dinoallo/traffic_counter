pub struct HttpMeta {
    pub host_ip: String,
    pub client_ip: String,
    pub host: String,
}

pub struct K8sIngressTraffic {
    pub http_meta: HttpMeta,
    pub svc_meta: SvcMeta,
    pub request_bytes: u64,
    pub response_bytes: u64,
}

pub struct L4Meta {
    pub local_ip: String,
    pub remote_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: String,
}

pub struct SvcMeta {
    pub namespace: String,
    pub service_name: String,
}

pub struct K8sNodePortTraffic {
    pub l4_meta: L4Meta,
    pub svc_meta: SvcMeta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

pub struct PodMeta {
    pub namespace: String,
    pub pod_name: String,
}

pub struct K8sPodToWorldTraffic {
    pub l4_meta: L4Meta,
    pub pod_meta: PodMeta,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

pub enum K8sTraffic {
    K8sIngress(K8sIngressTraffic),
    K8sNodePort(K8sNodePortTraffic),
    K8sPodToWorld(K8sPodToWorldTraffic),
}

pub enum Traffic {
    K8s(K8sTraffic),
    Unknown,
}
