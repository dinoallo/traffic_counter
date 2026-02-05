use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use futures::stream::TryStreamExt;
use netlink_packet_route::address::AddressAttribute::{Address, Local};
use tokio::sync::mpsc;
use tokio::{signal, task, time};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use api::proto::trafficcounter::v1::{
    IngestTrafficRequest, traffic_ingestor_client::TrafficIngestorClient,
};
use tracing::{debug, info};

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
}

#[derive(Clone)]
pub struct NodeRuntime {
    pub config: NodeConfig,
    remote_whitelist: Arc<AddressList>,
    host_aliases: Arc<AddressList>,
}

impl NodeRuntime {
    pub async fn new(opts: NodeOptions) -> Result<Self> {
        let NodeOptions { config } = opts;
        if config.workers == 0 {
            return Err(anyhow!("workers must be at least 1"));
        }
        validate_ring_config(&config.ring)?;

        let remote_whitelist = Arc::new(AddressList::from_option(
            config.remote_whitelist.as_deref(),
            "remote whitelist",
        )?);

        let iface_addrs = collect_iface_addrs(&config.iface)
            .await
            .with_context(|| format!("failed to resolve addresses for iface {}", config.iface))?;
        if iface_addrs.is_empty() {
            return Err(anyhow!(format!(
                "interface {} has no usable addresses",
                config.iface
            )));
        }
        let host_aliases = Arc::new(AddressList::from_addresses(iface_addrs));

        Ok(Self {
            config,
            remote_whitelist,
            host_aliases,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let config = &self.config;

        info!(
            "Connecting to traffic-counter server at {}",
            config.server_addr
        );
        let client = TrafficIngestorClient::connect(config.server_addr.clone())
            .await
            .context("failed to connect to traffic-counter server")?;
        info!("Connected to traffic-counter server");

        info!("Starting node on iface {}", config.iface);
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
        info!("Node started with {} workers", config.workers);

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

        let (stable_tx, mut stable_rx) = mpsc::channel::<IngestTrafficRequest>(1024);

        // Connection Manager Task
        let manager_client = client.clone();
        task::spawn(async move {
            let client = manager_client;
            loop {
                // Create ephemeral channel for the new stream
                let (stream_tx, stream_rx) = mpsc::channel(1024);
                let request_stream = ReceiverStream::new(stream_rx);

                let mut client_clone = client.clone();
                // Spawn the actual gRPC call
                let grpc_handle =
                    task::spawn(async move { client_clone.ingest_traffic(request_stream).await });

                // Forwarding loop: stable -> ephemeral
                loop {
                    let req = match stable_rx.recv().await {
                        Some(r) => r,
                        None => return, // Stable channel closed, worker shutting down
                    };

                    if stream_tx.send(req).await.is_err() {
                        eprintln!("Worker {worker_id}: gRPC stream broken, reconnecting...");
                        break; // Ephemeral channel closed (gRPC failed/ended)
                    }
                }

                // If we broke out, wait for the gRPC task to finish (it probably errored)
                let _ = grpc_handle.await;

                // Backoff before reconnecting
                time::sleep(Duration::from_secs(1)).await;
            }
        });

        // Pump loop writes to stable_tx
        socket
            .pump(
                &running,
                &self.remote_whitelist,
                &self.host_aliases,
                move |_, traffic| {
                    let tx = stable_tx.clone();
                    async move {
                        let req = IngestTrafficRequest {
                            traffic: Some(api::Traffic::NodePort(traffic).into()),
                        };
                        // We push to the stable buffer. If it's full (e.g. gRPC down and buffer full),
                        // this will backpressure (wait).
                        // If we wanted to drop packets when full, we'd use try_send.
                        // Here we await, effectively pausing capture if downstream is blocked.
                        if (tx.send(req).await).is_err() {
                            // Stable receiver closed (shouldn't happen unless manager task panics)
                            eprintln!("Worker {worker_id}: Stable channel closed unexpectedly");
                        } else {
                            // Successfully sent
                            debug!("Worker {worker_id}: Sent traffic data");
                        }
                    }
                },
            )
            .await
    }
}

async fn collect_iface_addrs(iface: &str) -> Result<Vec<IpAddr>> {
    let (connection, handle, _) =
        rtnetlink::new_connection().context("failed to create rtnetlink connection")?;
    tokio::spawn(connection);
    let mut addrs = Vec::new();
    let mut links = handle.link().get().match_name(iface.to_string()).execute();
    let index = if let Some(link) = links
        .try_next()
        .await
        .context("failed to get link information")?
    {
        link.header.index
    } else {
        return Err(anyhow!("interface {} not found", iface));
    };
    let mut messages = handle
        .address()
        .get()
        .set_link_index_filter(index) // This is the crucial filtering step
        .execute();

    while let Some(msg) = messages.try_next().await? {
        let attrs = msg.attributes;
        for attr in attrs {
            match attr {
                Address(ip_addr) | Local(ip_addr) => {
                    info!("Found address on {}: {}", iface, ip_addr);
                    addrs.push(ip_addr);
                }
                _ => continue,
            }
        }
    }
    Ok(addrs)
}

struct WorkerContext {
    iface: String,
    fanout_group: Option<u16>,
    ring_cfg: RingConfig,
    client: TrafficIngestorClient<Channel>,
}
