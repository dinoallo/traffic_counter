use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use tokio::{signal, task, time};

use crate::{
    export::Export,
    model::AddressList,
    packet::{PacketSocket, validate_ring_config},
    run::Run,
    store::CounterTable,
};

pub use crate::packet::RingConfig;

pub const DEFAULT_BLOCK_SIZE: u32 = 1 << 20; // 1 MiB
pub const DEFAULT_BLOCK_COUNT: u32 = 64;
pub const DEFAULT_FRAME_SIZE: u32 = 2048;
pub const DEFAULT_BLOCK_TIMEOUT_MS: u32 = 100;

pub struct NodeOptions {
    pub iface: String,
    pub workers: usize,
    pub fanout_group: Option<u16>,
    pub report_interval: Duration,
    pub report_natural: bool,
    pub ring: RingConfig,
    pub remote_whitelist: Option<PathBuf>,
    pub local_addresslist: Option<PathBuf>,
    pub exporter: Arc<dyn Export<Output = ()> + Send + Sync>,
}

pub struct NodeRuntime {
    iface: String,
    workers: usize,
    fanout_group: Option<u16>,
    report_interval: Duration,
    report_natural: bool,
    ring_cfg: RingConfig,
    remote_whitelist: Arc<AddressList>,
    local_addresslist: Arc<AddressList>,
    exporter: Arc<dyn Export<Output = ()> + Send + Sync>,
}

impl NodeRuntime {
    pub fn new(opts: NodeOptions) -> Result<Self> {
        if opts.workers == 0 {
            return Err(anyhow!("workers must be at least 1"));
        }
        if opts.report_interval.is_zero() {
            return Err(anyhow!("report interval must be greater than zero"));
        }
        validate_ring_config(&opts.ring)?;

        let remote_whitelist = Arc::new(AddressList::from_option(
            opts.remote_whitelist.as_deref(),
            "remote whitelist",
        )?);
        let local_addresslist = Arc::new(AddressList::from_option(
            opts.local_addresslist.as_deref(),
            "local address list",
        )?);

        Ok(Self {
            iface: opts.iface,
            workers: opts.workers,
            fanout_group: opts.fanout_group,
            report_interval: opts.report_interval,
            report_natural: opts.report_natural,
            ring_cfg: opts.ring,
            remote_whitelist,
            local_addresslist,
            exporter: opts.exporter,
        })
    }
}

#[async_trait]
impl Run for NodeRuntime {
    async fn run(&self) -> Result<()> {
        run_packet_pipeline(self).await
    }
}

async fn run_packet_pipeline(runtime: &NodeRuntime) -> Result<()> {
    let counters = Arc::new(CounterTable::default());
    let running = Arc::new(AtomicBool::new(true));

    let mut handles = Vec::with_capacity(runtime.workers);
    for worker_id in 0..runtime.workers {
        let counters_clone = counters.clone();
        let running_clone = running.clone();
        let remote_whitelist_clone = runtime.remote_whitelist.clone();
        let local_addresslist_clone = runtime.local_addresslist.clone();
        let ctx = WorkerContext {
            iface: runtime.iface.clone(),
            fanout_group: runtime.fanout_group,
            ring_cfg: runtime.ring_cfg,
        };
        handles.push(task::spawn(async move {
            worker_loop(
                worker_id,
                running_clone,
                counters_clone,
                ctx,
                remote_whitelist_clone,
                local_addresslist_clone,
            )
            .await
        }));
    }

    let reporter_table = counters.clone();
    let reporter_running = running.clone();
    let reporter_interval = runtime.report_interval;
    let reporter_natural = runtime.report_natural;
    let reporter_exporter = runtime.exporter.clone();
    let reporter = tokio::spawn(async move {
        run_reporter(
            reporter_table,
            reporter_running,
            reporter_interval,
            reporter_natural,
            reporter_exporter,
        )
        .await;
    });

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

    reporter.abort();
    let _ = reporter.await;

    runtime.exporter.export(counters.as_ref());
    Ok(())
}

async fn worker_loop(
    worker_id: usize,
    running: Arc<AtomicBool>,
    counters: Arc<CounterTable>,
    ctx: WorkerContext,
    remote_whitelist: Arc<AddressList>,
    local_addresslist: Arc<AddressList>,
) -> Result<()> {
    let WorkerContext {
        iface,
        fanout_group,
        ring_cfg,
    } = ctx;
    let mut socket = PacketSocket::bind(&iface, fanout_group, ring_cfg)
        .with_context(|| format!("worker {worker_id}: failed to bind packet socket"))?;
    socket
        .pump(&running, counters, &remote_whitelist, &local_addresslist)
        .await
}

async fn run_reporter(
    table: Arc<CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
    natural: bool,
    exporter: Arc<dyn Export<Output = ()> + Send + Sync>,
) {
    if natural {
        run_natural_reporter(table, running, interval, exporter).await;
    } else {
        run_interval_reporter(table, running, interval, exporter).await;
    }
}

async fn run_interval_reporter(
    table: Arc<CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
    exporter: Arc<dyn Export<Output = ()> + Send + Sync>,
) {
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        if !running.load(Ordering::Relaxed) {
            break;
        }
        exporter.export(table.as_ref());
    }
}

async fn run_natural_reporter(
    table: Arc<CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
    exporter: Arc<dyn Export<Output = ()> + Send + Sync>,
) {
    loop {
        let wait = duration_until_next_boundary(interval);
        time::sleep(wait).await;
        if !running.load(Ordering::Relaxed) {
            break;
        }
        exporter.export(table.as_ref());
    }
}

struct WorkerContext {
    iface: String,
    fanout_group: Option<u16>,
    ring_cfg: RingConfig,
}

fn duration_until_next_boundary(interval: Duration) -> Duration {
    if interval.is_zero() {
        return Duration::from_secs(0);
    }
    let now = SystemTime::now();
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let interval_ns = interval.as_nanos();
    if interval_ns == 0 {
        return Duration::from_secs(0);
    }
    let since_ns = since_epoch.as_nanos();
    let next_multiple = ((since_ns / interval_ns) + 1) * interval_ns;
    let wait_ns = next_multiple - since_ns;
    nanos_to_duration(wait_ns)
}

fn nanos_to_duration(ns: u128) -> Duration {
    const NS_PER_SEC: u128 = 1_000_000_000;
    let secs = (ns / NS_PER_SEC) as u64;
    let nanos = (ns % NS_PER_SEC) as u32;
    Duration::new(secs, nanos)
}
