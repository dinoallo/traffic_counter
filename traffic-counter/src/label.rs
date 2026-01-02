use crate::traffic::{
    K8sIngressTraffic, K8sNodePortTraffic, K8sPodToWorldTraffic, K8sTraffic, Traffic,
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait TrafficLabel<T>: Send + Sync
where
    T: Send + 'static,
{
    async fn label(&self, traffic: T) -> Result<T> {
        Ok(traffic)
    }
}

#[async_trait]
impl TrafficLabel<K8sIngressTraffic> for K8sTrafficLabeler {
    async fn label(&self, traffic: K8sIngressTraffic) -> Result<K8sIngressTraffic> {
        let result = self
            .k8s_inquirer
            .inquire_ingress(&traffic.http_meta)
            .await?;
        let Some(svc_meta) = result else {
            return Ok(traffic);
        };
        let labeled_traffic = K8sIngressTraffic {
            http_meta: traffic.http_meta,
            svc_meta,
            request_bytes: traffic.request_bytes,
            response_bytes: traffic.response_bytes,
        };
        Ok(labeled_traffic)
    }
}

#[async_trait]
impl TrafficLabel<K8sNodePortTraffic> for K8sTrafficLabeler {
    async fn label(&self, traffic: K8sNodePortTraffic) -> Result<K8sNodePortTraffic> {
        let result = self
            .k8s_inquirer
            .inquire_nodeport(&traffic.l4_meta)
            .await?;
        let Some(svc_meta) = result else {
            return Ok(traffic);
        };
        Ok(K8sNodePortTraffic {
            l4_meta: traffic.l4_meta,
            svc_meta,
            rx_bytes: traffic.rx_bytes,
            rx_packets: traffic.rx_packets,
            tx_bytes: traffic.tx_bytes,
            tx_packets: traffic.tx_packets,
        })
    }
}

#[async_trait]
impl TrafficLabel<K8sPodToWorldTraffic> for K8sTrafficLabeler {
    async fn label(&self, traffic: K8sPodToWorldTraffic) -> Result<K8sPodToWorldTraffic> {
        let result = self
            .k8s_inquirer
            .inquire_pod_to_world(&traffic.l4_meta)
            .await?;
        let Some(pod_meta) = result else {
            return Ok(traffic);
        };
        Ok(K8sPodToWorldTraffic {
            l4_meta: traffic.l4_meta,
            pod_meta,
            rx_bytes: traffic.rx_bytes,
            rx_packets: traffic.rx_packets,
            tx_bytes: traffic.tx_bytes,
            tx_packets: traffic.tx_packets,
        })
    }
}

#[async_trait]
impl TrafficLabel<K8sTraffic> for K8sTrafficLabeler {
    async fn label(&self, traffic: K8sTraffic) -> Result<K8sTraffic> {
        match traffic {
            K8sTraffic::K8sIngress(t) => {
                let labeled = self.label(t).await?;
                Ok(K8sTraffic::K8sIngress(labeled))
            }
            K8sTraffic::K8sNodePort(t) => {
                let labeled = self.label(t).await?;
                Ok(K8sTraffic::K8sNodePort(labeled))
            }
            K8sTraffic::K8sPodToWorld(t) => {
                let labeled = self.label(t).await?;
                Ok(K8sTraffic::K8sPodToWorld(labeled))
            }
        }
    }
}
pub struct K8sTrafficLabeler {
    k8s_inquirer: Arc<dyn crate::k8s::K8sInquire + Send + Sync>,
}

pub struct TrafficLabeler {
    pub k8s_labeler: K8sTrafficLabeler,
}

#[async_trait]
impl TrafficLabel<Traffic> for TrafficLabeler {
    async fn label(&self, traffic: Traffic) -> Result<Traffic> {
        match traffic {
            Traffic::K8s(t) => {
                let labeled = self.k8s_labeler.label(t).await?;
                Ok(Traffic::K8s(labeled))
            }
            Traffic::L4(_) => Ok(traffic),
            Traffic::Unknown => Ok(traffic),
        }
    }
}