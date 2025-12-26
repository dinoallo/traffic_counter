use crate::traffic::{K8sNodePortTraffic, K8sPodToWorldTraffic};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct HttpCounter {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub gateway_ip: String,
    pub client_ip: String,
    pub host: String,
}

#[derive(Clone, Debug)]
pub struct L4Counter {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl std::fmt::Display for HttpCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HTTP Counter - gateway_ip: {} client_ip: {} host: {} rx_bytes: {} tx_bytes: {}",
            self.gateway_ip, self.client_ip, self.host, self.rx_bytes, self.tx_bytes
        )
    }
}

impl std::fmt::Display for L4Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "L4 Counter - rx_bytes: {} rx_packets: {} tx_bytes: {} tx_packets: {}",
            self.rx_bytes, self.rx_packets, self.tx_bytes, self.tx_packets
        )
    }
}

#[allow(dead_code)]
pub enum Counter {
    Http(HttpCounter),
    L4(L4Counter),
    Unknown,
}

impl std::fmt::Display for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Counter::Http(counter) => counter.fmt(f),
            Counter::L4(counter) => counter.fmt(f),
            Counter::Unknown => write!(f, "Unknown Counter"),
        }
    }
}
pub trait TrafficCount<T> {
    fn increment(&mut self, traffic: T);
    fn clear(&mut self);
}

impl TrafficCount<K8sNodePortTraffic> for K8sNodePortTraffic {
    fn increment(&mut self, traffic: K8sNodePortTraffic) {
        self.rx_bytes += traffic.rx_bytes;
        self.rx_packets += traffic.rx_packets;
        self.tx_bytes += traffic.tx_bytes;
        self.tx_packets += traffic.tx_packets;
    }

    fn clear(&mut self) {
        self.rx_bytes = 0;
        self.rx_packets = 0;
        self.tx_bytes = 0;
        self.tx_packets = 0;
    }
}
