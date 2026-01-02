use crate::store::CounterTable;
use crate::traffic::{K8sNodePortTraffic, L4Meta, L4Traffic};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct HttpCounter {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub gateway_ip: String,
    pub client_ip: String,
    pub host: String,
}

pub type L4CounterTable = CounterTable<L4Meta, L4Traffic>;

impl std::fmt::Display for HttpCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HTTP Counter - gateway_ip: {} client_ip: {} host: {} rx_bytes: {} tx_bytes: {}",
            self.gateway_ip, self.client_ip, self.host, self.rx_bytes, self.tx_bytes
        )
    }
}

pub trait TrafficCount<T> {
    fn increment(&mut self, traffic: T);
    fn clear(&mut self);
}

impl TrafficCount<L4Traffic> for L4Traffic {
    fn increment(&mut self, traffic: L4Traffic) {
        // We accumulate the metadata if ours is empty/default (first write)
        // or just keep ours. Since key implies metadata, the value's metadata is redundant
        // but should remain consistent.
        if self.l4_meta.local_port == 0 && traffic.l4_meta.local_port != 0 {
            self.l4_meta = traffic.l4_meta;
        }

        self.rx_bytes += traffic.rx_bytes;
        self.rx_packets += traffic.rx_packets;
        self.tx_bytes += traffic.tx_bytes;
        self.tx_packets += traffic.tx_packets;
    }

    fn clear(&mut self) {
        // We preserve the metadata when clearing counters?
        // Usually clearing means reset stats to 0.
        // If we reset to Default::default(), we lose metadata.
        // Let's just reset stats.
        self.rx_bytes = 0;
        self.rx_packets = 0;
        self.tx_bytes = 0;
        self.tx_packets = 0;
    }
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
