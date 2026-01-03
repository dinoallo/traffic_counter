use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use chrono::Utc;
use tokio::time;

use crate::store::TrafficDump;

/// Trait representing anything that can export itself into another form.
pub trait Export: Send + Sync {
    /// Perform the export and return the resulting value.
    async fn run(&self, running: Arc<AtomicBool>, interval: Duration, natural: bool) -> Result<()>;
}

#[derive(Clone)]
pub struct LogExporter {
    traffic_dumper: Arc<dyn TrafficDump>,
}

impl Export for LogExporter {
    async fn run(&self, running: Arc<AtomicBool>, interval: Duration, natural: bool) -> Result<()> {
        if natural {
            self.run_at_natural_interval(running, interval).await
        } else {
            self.run_at_interval(running, interval).await
        }
    }
}

impl LogExporter {
    pub fn new(traffic_dumper: Arc<dyn TrafficDump>) -> Self {
        Self { traffic_dumper }
    }
    async fn run_at_interval(&self, running: Arc<AtomicBool>, interval: Duration) -> Result<()> {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            if !running.load(Ordering::Relaxed) {
                break;
            }
            let timestamp = Utc::now();
            let records = self.traffic_dumper.dump();
            for record in records {
                println!("{} - Exported Record: {}", timestamp.to_rfc3339(), record);
            }
        }
        Ok(())
    }

    async fn run_at_natural_interval(
        &self,
        running: Arc<AtomicBool>,
        interval: Duration,
    ) -> Result<()> {
        loop {
            let wait = duration_until_next_boundary(interval);
            time::sleep(wait).await;
            if !running.load(Ordering::Relaxed) {
                break;
            }
            let timestamp = Utc::now();
            let records = self.traffic_dumper.dump();
            for record in records {
                println!("{} - Exported Record: {}", timestamp.to_rfc3339(), record);
            }
        }
        Ok(())
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
