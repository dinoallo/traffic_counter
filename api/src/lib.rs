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

pub mod proto {
    pub mod trafficcounter {
        pub mod v1 {
            tonic::include_proto!("trafficcounter.v1");
        }
    }
}

use proto::trafficcounter::v1 as pb;
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoConversionError {
    #[error("field '{0}' is required")]
    MissingField(&'static str),
    #[error("value in field '{0}' exceeds supported range")]
    OutOfRange(&'static str),
    #[error("invalid IP address in field '{0}'")]
    InvalidIp(&'static str),
}

impl TryFrom<pb::Traffic> for Traffic {
    type Error = ProtoConversionError;

    fn try_from(value: pb::Traffic) -> Result<Self, Self::Error> {
        use pb::traffic::Kind;

        match value
            .kind
            .ok_or(ProtoConversionError::MissingField("traffic.kind"))?
        {
            Kind::HttpGateway(ingress) => {
                Ok(Traffic::HttpGateway(HttpGatewayTraffic::try_from(ingress)?))
            }
            Kind::NodePort(node_port) => {
                Ok(Traffic::NodePort(NodePortTraffic::try_from(node_port)?))
            }
            Kind::Cluster(cluster) => Ok(Traffic::Cluster(ClusterTraffic::try_from(cluster)?)),
        }
    }
}

impl TryFrom<pb::HttpGatewayTraffic> for HttpGatewayTraffic {
    type Error = ProtoConversionError;

    fn try_from(value: pb::HttpGatewayTraffic) -> Result<Self, Self::Error> {
        let http_meta = require(value.http_meta, "http_gateway.http_meta")?;

        Ok(HttpGatewayTraffic {
            http_meta: HttpMeta {
                host_ip: http_meta.host_ip,
                client_ip: http_meta.client_ip,
                host: http_meta.host,
            },
            request_bytes: value.request_bytes,
            response_bytes: value.response_bytes,
        })
    }
}

impl TryFrom<pb::NodePortTraffic> for NodePortTraffic {
    type Error = ProtoConversionError;

    fn try_from(value: pb::NodePortTraffic) -> Result<Self, Self::Error> {
        let l4_meta = require(value.l4_meta, "node_port.l4_meta")?;

        Ok(NodePortTraffic {
            l4_meta: convert_l4_meta(l4_meta)?,
            rx_bytes: value.rx_bytes,
            rx_packets: value.rx_packets,
            tx_bytes: value.tx_bytes,
            tx_packets: value.tx_packets,
        })
    }
}

impl TryFrom<pb::ClusterTraffic> for ClusterTraffic {
    type Error = ProtoConversionError;

    fn try_from(value: pb::ClusterTraffic) -> Result<Self, Self::Error> {
        let l4_meta = require(value.l4_meta, "cluster.l4_meta")?;

        Ok(ClusterTraffic {
            l4_meta: convert_l4_meta(l4_meta)?,
            rx_bytes: value.rx_bytes,
            rx_packets: value.rx_packets,
            tx_bytes: value.tx_bytes,
            tx_packets: value.tx_packets,
        })
    }
}

fn convert_l4_meta(meta: pb::L4Meta) -> Result<L4Meta, ProtoConversionError> {
    Ok(L4Meta {
        local_ip: meta
            .local_ip
            .parse()
            .map_err(|_| ProtoConversionError::InvalidIp("l4_meta.local_ip"))?,
        remote_ip: meta
            .remote_ip
            .parse()
            .map_err(|_| ProtoConversionError::InvalidIp("l4_meta.remote_ip"))?,
        local_port: as_u16(meta.local_port, "l4_meta.local_port")?,
        remote_port: as_u16(meta.remote_port, "l4_meta.remote_port")?,
        protocol: meta.protocol as u8,
    })
}

fn require<T>(value: Option<T>, field: &'static str) -> Result<T, ProtoConversionError> {
    value.ok_or(ProtoConversionError::MissingField(field))
}

fn as_u16(value: u32, field: &'static str) -> Result<u16, ProtoConversionError> {
    u16::try_from(value).map_err(|_| ProtoConversionError::OutOfRange(field))
}

impl From<Traffic> for pb::Traffic {
    fn from(traffic: Traffic) -> Self {
        use pb::traffic::Kind;
        match traffic {
            Traffic::NodePort(t) => pb::Traffic {
                kind: Some(Kind::NodePort(t.into())),
            },
            Traffic::HttpGateway(t) => pb::Traffic {
                kind: Some(Kind::HttpGateway(t.into())),
            },
            Traffic::Cluster(t) => pb::Traffic {
                kind: Some(Kind::Cluster(t.into())),
            },
        }
    }
}

impl From<HttpGatewayTraffic> for pb::HttpGatewayTraffic {
    fn from(t: HttpGatewayTraffic) -> Self {
        pb::HttpGatewayTraffic {
            http_meta: Some(t.http_meta.into()),
            request_bytes: t.request_bytes,
            response_bytes: t.response_bytes,
        }
    }
}

impl From<NodePortTraffic> for pb::NodePortTraffic {
    fn from(t: NodePortTraffic) -> Self {
        pb::NodePortTraffic {
            l4_meta: Some(t.l4_meta.into()),
            rx_bytes: t.rx_bytes,
            rx_packets: t.rx_packets,
            tx_bytes: t.tx_bytes,
            tx_packets: t.tx_packets,
        }
    }
}

impl From<ClusterTraffic> for pb::ClusterTraffic {
    fn from(t: ClusterTraffic) -> Self {
        pb::ClusterTraffic {
            l4_meta: Some(t.l4_meta.into()),
            rx_bytes: t.rx_bytes,
            rx_packets: t.rx_packets,
            tx_bytes: t.tx_bytes,
            tx_packets: t.tx_packets,
        }
    }
}

impl From<HttpMeta> for pb::HttpMeta {
    fn from(m: HttpMeta) -> Self {
        pb::HttpMeta {
            host_ip: m.host_ip,
            client_ip: m.client_ip,
            host: m.host,
        }
    }
}

impl From<L4Meta> for pb::L4Meta {
    fn from(m: L4Meta) -> Self {
        pb::L4Meta {
            local_ip: m.local_ip.to_string(),
            remote_ip: m.remote_ip.to_string(),
            local_port: m.local_port as u32,
            remote_port: m.remote_port as u32,
            protocol: m.protocol as u32,
        }
    }
}
