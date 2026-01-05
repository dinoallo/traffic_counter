use crate::label::{TrafficLabel, TrafficLabeler};
use crate::store::{TrafficAggregate, TrafficCounter};
use anyhow::{Result, anyhow};
use api::Traffic;
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    sync::{Mutex, mpsc},
    task,
};
use tracing::warn;

#[cfg(test)]
use std::collections::VecDeque;
#[cfg(test)]
use tokio::sync::Notify;

/// Processing contract for traffic pipelines.
#[async_trait]
pub trait TrafficProcess: Send + Sync {
    /// Accept raw traffic from any producer. Implementations should avoid blocking
    /// producers and perform minimal work before returning.
    async fn input(&self, traffic: Traffic) -> Result<()>;

    async fn start_processing(&self) -> Result<()>;
}

/// A simple in-memory factory that buffers traffic between producers and consumers.
pub struct TrafficFactory {
    sender: mpsc::UnboundedSender<Traffic>,
    ingress: Mutex<Option<mpsc::UnboundedReceiver<Traffic>>>,
    started: AtomicBool,
    labeler: Arc<TrafficLabeler>,
    aggregator: Arc<TrafficCounter>,
}

impl TrafficFactory {
    /// Create a factory backed by unbounded channels so producers never block.
    pub fn new(labeler: Arc<TrafficLabeler>, aggregator: Arc<TrafficCounter>) -> Self {
        let (ingress_tx, ingress_rx) = mpsc::unbounded_channel();

        Self {
            sender: ingress_tx,
            ingress: Mutex::new(Some(ingress_rx)),
            started: AtomicBool::new(false),
            labeler,
            aggregator,
        }
    }
}

#[cfg(test)]
pub struct DummyTrafficFactory {
    buffer: Mutex<VecDeque<Traffic>>,
    notify: Notify,
}

#[cfg(test)]
impl DummyTrafficFactory {
    pub fn new() -> Self {
        Self {
            buffer: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }
}

#[cfg(test)]
impl Default for DummyTrafficFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TrafficProcess for TrafficFactory {
    async fn input(&self, traffic: Traffic) -> Result<()> {
        self.sender
            .send(traffic)
            .map_err(|err| anyhow!("failed to enqueue traffic: {err}"))
    }

    async fn start_processing(&self) -> Result<()> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let mut ingress_guard = self.ingress.lock().await;
        let Some(mut ingress_rx) = ingress_guard.take() else {
            return Err(anyhow!("ingress channel unavailable"));
        };
        drop(ingress_guard);

        let labeler = self.labeler.clone();
        let aggregator = self.aggregator.clone();

        task::spawn(async move {
            while let Some(traffic) = ingress_rx.recv().await {
                match traffic {
                    Traffic::NodePort(t) => match labeler.label(&t).await {
                        Ok(Some(label)) => aggregator.aggregate(label, t),
                        Ok(None) => {}
                        Err(err) => warn!("failed to label nodeport traffic: {err:?}"),
                    },
                    Traffic::HttpGateway(t) => match labeler.label(&t).await {
                        Ok(Some(label)) => aggregator.aggregate(label, t),
                        Ok(None) => {}
                        Err(err) => warn!("failed to label http gateway traffic: {err:?}"),
                    },
                    Traffic::Cluster(t) => match labeler.label(&t).await {
                        Ok(Some(label)) => aggregator.aggregate(label, t),
                        Ok(None) => {}
                        Err(err) => warn!("failed to label cluster traffic: {err:?}"),
                    },
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
#[async_trait]
impl TrafficProcess for DummyTrafficFactory {
    async fn input(&self, traffic: Traffic) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        buffer.push_back(traffic);
        drop(buffer);
        self.notify.notify_one();
        Ok(())
    }

    async fn start_processing(&self) -> Result<()> {
        Ok(())
    }
}
