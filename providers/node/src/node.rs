use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
use tokio::{signal, task};
use tonic::transport::Channel;

use api::proto::trafficcounter::v1::{
    IngestTrafficRequest, traffic_ingestor_client::TrafficIngestorClient,
};

pub use crate::packet::RingConfig;
use crate::{
    model::AddressList,
    packet::{PacketSocket, validate_ring_config},
};

pub const DEFAULT_BLOCK_SIZE: u32 = 1 << 20; // 1 MiB
pub const DEFAULT_BLOCK_COUNT: u32 = 64;
pub const DEFAULT_FRAME_SIZE: u32 = 2048;
pub const DEFAULT_BLOCK_TIMEOUT_MS: u32 = 100;

// NodeOptions encapsulates all internal and external options needed to run a node
pub struct NodeOptions {
    pub config: NodeConfig,
}

// NodeConfig can be configured from CLI or other sources
#[derive(Clone)]
pub struct NodeConfig {
    pub server_addr: String,
    pub iface: String,
    pub workers: usize,
    pub fanout_group: Option<u16>,
    pub ring: RingConfig,
    pub remote_whitelist: Option<PathBuf>,
    pub local_addresslist: Option<PathBuf>,
}

#[derive(Clone)]
pub struct NodeRuntime {
    pub config: NodeConfig,
    remote_whitelist: Arc<AddressList>,
    local_addresslist: Arc<AddressList>,
}

impl NodeRuntime {
    pub fn new(opts: NodeOptions) -> Result<Self> {
        let NodeOptions { config } = opts;
        if config.workers == 0 {
            return Err(anyhow!("workers must be at least 1"));
        }
        validate_ring_config(&config.ring)?;

        let remote_whitelist = Arc::new(AddressList::from_option(
            config.remote_whitelist.as_deref(),
            "remote whitelist",
        )?);
        let local_addresslist = Arc::new(AddressList::from_option(
            config.local_addresslist.as_deref(),
            "local address list",
        )?);

        Ok(Self {
            config,
            remote_whitelist,
            local_addresslist,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let config = &self.config;

        let client = TrafficIngestorClient::connect(config.server_addr.clone())
            .await
            .context("failed to connect to traffic-counter server")?;

        let mut handles = Vec::with_capacity(config.workers);
        for worker_id in 0..config.workers {
            let running_clone = running.clone();
            let client_clone = client.clone();
            let ctx = WorkerContext {
                iface: config.iface.clone(),
                fanout_group: config.fanout_group,
                ring_cfg: config.ring,
                client: client_clone,
            };
            let runtime = self.clone();
            handles.push(task::spawn(async move {
                runtime.worker_loop(worker_id, running_clone, ctx).await
            }));
        }

        signal::ctrl_c()
            .await
            .context("failed to wait for ctrl-c")?;
        println!("Received shutdown signal, draining...");
        running.store(false, Ordering::Relaxed);

        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(anyhow!("worker panicked: {err}")),
            }
        }

        Ok(())
    }

    async fn worker_loop(
        &self,
        worker_id: usize,
        running: Arc<AtomicBool>,
        ctx: WorkerContext,
    ) -> Result<()> {
        let WorkerContext {
            iface,
            fanout_group,
            ring_cfg,
            client,
        } = ctx;
        let mut socket = PacketSocket::bind(&iface, fanout_group, ring_cfg)
            .with_context(|| format!("worker {worker_id}: failed to bind packet socket"))?;

        socket
            .pump(
                &running,
                &self.remote_whitelist,
                &self.local_addresslist,
                move |_, traffic| {
                    let mut client = client.clone();
                    async move {
                        let req = IngestTrafficRequest {
                            traffic: Some(api::Traffic::NodePort(traffic).into()),
                        };
                        // TODO: Batching or fire-and-forget to avoid stalling the pump loop too much?
                        // For now, we await. pump calls this in a loop.
                        // If gRPC is slow, packet capture will drop packets.
                        if let Err(e) = client.ingest_traffic(req).await {
                            eprintln!("Failed to ingest traffic: {e}");
                        }
                    }
                },
            )
            .await
    }
}

struct WorkerContext {
    iface: String,
    fanout_group: Option<u16>,
    ring_cfg: RingConfig,
    client: TrafficIngestorClient<Channel>,
}

