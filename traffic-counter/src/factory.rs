use crate::{label::TrafficLabel, label::TrafficLabeler, traffic::Traffic};
use anyhow::{Result, anyhow};
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

    /// Emit the next processed traffic item, waiting until one is available.
    async fn output(&self) -> Result<Traffic>;

    async fn start_processing(&self) -> Result<()>;
}

/// A simple in-memory factory that buffers traffic between producers and consumers.
pub struct TrafficFactory {
    sender: mpsc::UnboundedSender<Traffic>,
    ingress: Mutex<Option<mpsc::UnboundedReceiver<Traffic>>>,
    receiver: Mutex<mpsc::UnboundedReceiver<Traffic>>,
    egress_sender: mpsc::UnboundedSender<Traffic>,
    labeler: Arc<TrafficLabeler>,
    started: AtomicBool,
}

impl TrafficFactory {
    /// Create a factory backed by unbounded channels so producers never block.
    pub fn new(labeler: Arc<TrafficLabeler>) -> Self {
        let (ingress_tx, ingress_rx) = mpsc::unbounded_channel();
        let (egress_tx, egress_rx) = mpsc::unbounded_channel();

        Self {
            sender: ingress_tx,
            ingress: Mutex::new(Some(ingress_rx)),
            receiver: Mutex::new(egress_rx),
            egress_sender: egress_tx,
            labeler,
            started: AtomicBool::new(false),
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

    async fn output(&self) -> Result<Traffic> {
        let mut receiver = self.receiver.lock().await;
        receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("traffic channel closed"))
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

        let labeler = Arc::clone(&self.labeler);
        let egress_tx = self.egress_sender.clone();

        task::spawn(async move {
            while let Some(traffic) = ingress_rx.recv().await {
                match labeler.label(traffic).await {
                    Ok(labeled) => {
                        if egress_tx.send(labeled).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        warn!("failed to label traffic: {err:?}");
                    }
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

    async fn output(&self) -> Result<Traffic> {
        loop {
            if let Some(item) = {
                let mut buffer = self.buffer.lock().await;
                buffer.pop_front()
            } {
                return Ok(item);
            }
            self.notify.notified().await;
        }
    }

    async fn start_processing(&self) -> Result<()> {
        Ok(())
    }
}
