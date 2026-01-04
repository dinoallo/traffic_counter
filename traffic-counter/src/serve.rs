use std::{convert::TryFrom, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use api::Traffic;
use clap::Args;
use thiserror::Error;
use tonic::{Request, Response, Status, transport::Server as TonicServer};

use crate::factory::TrafficProcess;

mod proto {
    pub mod trafficcounter {
        pub mod v1 {
            tonic::include_proto!("trafficcounter.v1");
        }
    }
}

use proto::trafficcounter::v1 as pb;

#[derive(Debug, Clone, Args)]
pub struct ServeConfig {
    /// Address the gRPC server binds to, e.g. 0.0.0.0:50051
    #[arg(
        long = "grpc-listen-addr",
        env = "TRAFFIC_COUNTER_GRPC_ADDR",
        default_value = "0.0.0.0:50051"
    )]
    pub listen_addr: SocketAddr,
}

pub struct Server<P>
where
    P: TrafficProcess + 'static,
{
    config: ServeConfig,
    process: Arc<P>,
}

impl<P> Server<P>
where
    P: TrafficProcess + 'static,
{
    pub fn new(config: ServeConfig, process: Arc<P>) -> Self {
        Self { config, process }
    }

    pub async fn run(self) -> Result<()> {
        self.process.start_processing().await?;

        let addr = self.config.listen_addr;
        let service = TrafficService::new(self.process);

        TonicServer::builder()
            .add_service(pb::traffic_ingestor_server::TrafficIngestorServer::new(
                service,
            ))
            .serve(addr)
            .await
            .with_context(|| format!("failed to start gRPC server on {addr}"))
    }
}

struct TrafficService<P>
where
    P: TrafficProcess + 'static,
{
    process: Arc<P>,
}

impl<P> TrafficService<P>
where
    P: TrafficProcess + 'static,
{
    fn new(process: Arc<P>) -> Self {
        Self { process }
    }
}

#[tonic::async_trait]
impl<P> pb::traffic_ingestor_server::TrafficIngestor for TrafficService<P>
where
    P: TrafficProcess + 'static,
{
    async fn ingest_traffic(
        &self,
        request: Request<pb::IngestTrafficRequest>,
    ) -> Result<Response<pb::IngestTrafficResponse>, Status> {
        let pb_request = request.into_inner();
        let traffic = pb_request
            .traffic
            .ok_or(ProtoConversionError::MissingField("traffic"))
            .and_then(Traffic::try_from)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        self.process
            .input(traffic)
            .await
            .map_err(|err| Status::internal(format!("failed to enqueue traffic: {err}")))?;

        Ok(Response::new(pb::IngestTrafficResponse {}))
    }
}

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
            Kind::HttpGateway(ingress) => Ok(api::Traffic::HttpGateway(
                api::HttpGatewayTraffic::try_from(ingress)?,
            )),
            Kind::NodePort(node_port) => Ok(api::Traffic::NodePort(
                api::NodePortTraffic::try_from(node_port)?,
            )),
            Kind::Cluster(cluster) => Ok(api::Traffic::Cluster(api::ClusterTraffic::try_from(
                cluster,
            )?)),
        }
    }
}

impl TryFrom<pb::HttpGatewayTraffic> for api::HttpGatewayTraffic {
    type Error = ProtoConversionError;

    fn try_from(value: pb::HttpGatewayTraffic) -> Result<Self, Self::Error> {
        let http_meta = require(value.http_meta, "http_gateway.http_meta")?;

        Ok(api::HttpGatewayTraffic {
            http_meta: api::HttpMeta {
                host_ip: http_meta.host_ip,
                client_ip: http_meta.client_ip,
                host: http_meta.host,
            },
            request_bytes: value.request_bytes,
            response_bytes: value.response_bytes,
        })
    }
}

impl TryFrom<pb::NodePortTraffic> for api::NodePortTraffic {
    type Error = ProtoConversionError;

    fn try_from(value: pb::NodePortTraffic) -> Result<Self, Self::Error> {
        let l4_meta = require(value.l4_meta, "node_port.l4_meta")?;

        Ok(api::NodePortTraffic {
            l4_meta: convert_l4_meta(l4_meta)?,
            rx_bytes: value.rx_bytes,
            rx_packets: value.rx_packets,
            tx_bytes: value.tx_bytes,
            tx_packets: value.tx_packets,
        })
    }
}

impl TryFrom<pb::ClusterTraffic> for api::ClusterTraffic {
    type Error = ProtoConversionError;

    fn try_from(value: pb::ClusterTraffic) -> Result<Self, Self::Error> {
        let l4_meta = require(value.l4_meta, "cluster.l4_meta")?;

        Ok(api::ClusterTraffic {
            l4_meta: convert_l4_meta(l4_meta)?,
            rx_bytes: value.rx_bytes,
            rx_packets: value.rx_packets,
            tx_bytes: value.tx_bytes,
            tx_packets: value.tx_packets,
        })
    }
}

fn convert_l4_meta(meta: pb::L4Meta) -> Result<api::L4Meta, ProtoConversionError> {
    Ok(api::L4Meta {
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
        protocol: parse_protocol(&meta.protocol),
    })
}

fn parse_protocol(proto: &str) -> u8 {
    match proto.to_lowercase().as_str() {
        "tcp" | "6" => 6,
        "udp" | "17" => 17,
        "icmp" | "1" => 1,
        _ => proto.parse().unwrap_or(0),
    }
}

fn require<T>(value: Option<T>, field: &'static str) -> Result<T, ProtoConversionError> {
    value.ok_or(ProtoConversionError::MissingField(field))
}

fn as_u16(value: u32, field: &'static str) -> Result<u16, ProtoConversionError> {
    u16::try_from(value).map_err(|_| ProtoConversionError::OutOfRange(field))
}

fn as_u8(value: u32, field: &'static str) -> Result<u8, ProtoConversionError> {
    u8::try_from(value).map_err(|_| ProtoConversionError::OutOfRange(field))
}
