use std::{convert::TryFrom, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use api::Traffic;
use clap::Args;
use tonic::{Request, Response, Status, transport::Server as TonicServer};

use crate::factory::TrafficProcess;

use api::ProtoConversionError;

use api::proto::trafficcounter::v1 as pb;

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
