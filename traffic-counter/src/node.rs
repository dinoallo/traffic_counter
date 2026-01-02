use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use tokio::{signal, task};

use crate::factory::TrafficProcess;
pub use crate::packet::RingConfig;
use crate::traffic::Traffic;
use crate::{
    model::AddressList,
    packet::{PacketSocket, validate_ring_config},
    run::Run,
};

pub const DEFAULT_BLOCK_SIZE: u32 = 1 << 20; // 1 MiB
pub const DEFAULT_BLOCK_COUNT: u32 = 64;
pub const DEFAULT_FRAME_SIZE: u32 = 2048;
pub const DEFAULT_BLOCK_TIMEOUT_MS: u32 = 100;

// NodeOptions encapsulates all internal and external options needed to run a node
pub struct NodeOptions {
    pub config: NodeConfig,
    pub traffic_processor: Arc<dyn TrafficProcess>,
}

// NodeConfig can be configured from CLI or other sources
#[derive(Clone)]
pub struct NodeConfig {
    pub iface: String,
    pub workers: usize,
    pub fanout_group: Option<u16>,
    /*     pub report_interval: Duration,
    pub report_natural: bool, */
    pub ring: RingConfig,
    pub remote_whitelist: Option<PathBuf>,
    pub local_addresslist: Option<PathBuf>,
}

#[derive(Clone)]
pub struct NodeRuntime {
    pub config: NodeConfig,
    traffic_processor: Arc<dyn TrafficProcess>,
    remote_whitelist: Arc<AddressList>,
    local_addresslist: Arc<AddressList>,
}

impl NodeRuntime {
    pub fn new(opts: NodeOptions) -> Result<Self> {
        let NodeOptions {
            config,
            traffic_processor,
        } = opts;
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
            traffic_processor,
        })
    }

    async fn run_packet_pipeline(&self, runtime: &NodeRuntime) -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let config = &runtime.config;

        let mut handles = Vec::with_capacity(config.workers);
        for worker_id in 0..config.workers {
            let running_clone = running.clone();
            let ctx = WorkerContext {
                iface: config.iface.clone(),
                fanout_group: config.fanout_group,
                ring_cfg: config.ring,
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
        } = ctx;
        let mut socket = PacketSocket::bind(&iface, fanout_group, ring_cfg)
            .with_context(|| format!("worker {worker_id}: failed to bind packet socket"))?;
        socket
            .pump(
                &running,
                &self.remote_whitelist,
                &self.local_addresslist,
                move |_, traffic| async move {
                    let _ = self.traffic_processor.input(Traffic::L4(traffic)).await;
                },
            )
            .await
    }
}

#[async_trait]
impl Run for NodeRuntime {
    async fn run(&self) -> Result<()> {
        self.run_packet_pipeline(self).await
    }
}

struct WorkerContext {
    iface: String,
    fanout_group: Option<u16>,
    ring_cfg: RingConfig,
}
