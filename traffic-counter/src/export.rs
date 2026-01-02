use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::counter::L4CounterTable;
use chrono::Utc;
use tokio::time;

/// Trait representing anything that can export itself into another form.
pub trait Export: Send + Sync {
    /// The result type returned by the export operation.
    type Output;

    /// Perform the export and return the resulting value.
    fn export(&self, table: &L4CounterTable) -> Self::Output;
}

#[derive(Debug, Default, Copy, Clone)]
pub struct LogExporter;

impl Export for LogExporter {
    type Output = ();

    fn export(&self, table: &L4CounterTable) -> Self::Output {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        for shard in &table.shards {
            let mut guard = shard.lock().expect("counter shard mutex poisoned");
            for (l4_meta, l4_traffic) in guard.iter() {
                println!("[{timestamp}] flow {} - counter {}", l4_meta, l4_traffic);
            }
            guard.clear();
        }
    }
}

pub async fn run_reporter(
    table: Arc<L4CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
    natural: bool,
    exporter: Arc<dyn Export<Output = ()>>,
) {
    if natural {
        run_natural_reporter(table, running, interval, exporter).await;
    } else {
        run_interval_reporter(table, running, interval, exporter).await;
    }
}

async fn run_interval_reporter(
    table: Arc<L4CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
    exporter: Arc<dyn Export<Output = ()>>,
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
    table: Arc<L4CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
    exporter: Arc<dyn Export<Output = ()>>,
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
