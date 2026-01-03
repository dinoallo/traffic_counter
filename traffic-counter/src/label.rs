use anyhow::Result;
use api::{ClusterTraffic, HttpGatewayTraffic, NodePortTraffic};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct ReservedPortLabel {
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct K8sNodePortLabel {
    pub namespace: String,
    pub service_name: String,
    // pub port_name: String,
    // pub port_protocol: String,
    // pub node_port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct DynamicPortLabel {
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NodePortLabel {
    ReservedPort(ReservedPortLabel),
    K8sNodePort(K8sNodePortLabel),
    DynamicPort(DynamicPortLabel),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct K8sPodLabel {
    pub namespace: String,
    pub pod_name: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ClusterLabel {
    K8sPod(K8sPodLabel),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct K8sIngressLabel {
    pub namespace: String,
    pub service_name: String,
    pub host: String,
    // pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum HttpGatewayLabel {
    K8sIngress(K8sIngressLabel),
}

#[async_trait]
pub trait TrafficLabel<T, L>: Send + Sync
where
    T: Send + 'static,
{
    async fn label(&self, traffic: T) -> Result<Option<L>>;
}

#[async_trait]
impl TrafficLabel<HttpGatewayTraffic, HttpGatewayLabel> for K8sTrafficLabeler {
    async fn label(&self, traffic: HttpGatewayTraffic) -> Result<Option<HttpGatewayLabel>> {
        let result = self
            .k8s_inquirer
            .inquire_ingress(&traffic.http_meta)
            .await?;
        let Some(svc_meta) = result else {
            return Ok(None);
        };
        let l = HttpGatewayLabel::K8sIngress(K8sIngressLabel {
            namespace: svc_meta.namespace,
            service_name: svc_meta.service_name,
            host: traffic.http_meta.host,
        });
        Ok(Some(l))
    }
}

#[async_trait]
impl TrafficLabel<NodePortTraffic, NodePortLabel> for K8sTrafficLabeler {
    async fn label(&self, traffic: NodePortTraffic) -> Result<Option<NodePortLabel>> {
        let result = self.k8s_inquirer.inquire_nodeport(&traffic.l4_meta).await?;
        let Some(svc_meta) = result else {
            return Ok(None);
        };
        let l = NodePortLabel::K8sNodePort(K8sNodePortLabel {
            namespace: svc_meta.namespace,
            service_name: svc_meta.service_name,
        });
        Ok(Some(l))
    }
}

#[async_trait]
impl TrafficLabel<ClusterTraffic, ClusterLabel> for K8sTrafficLabeler {
    async fn label(&self, traffic: ClusterTraffic) -> Result<Option<ClusterLabel>> {
        let result = self
            .k8s_inquirer
            .inquire_pod_to_world(&traffic.l4_meta)
            .await?;
        let Some(pod_meta) = result else {
            return Ok(None);
        };
        let l = ClusterLabel::K8sPod(K8sPodLabel {
            namespace: pod_meta.namespace,
            pod_name: pod_meta.pod_name,
        });
        Ok(Some(l))
    }
}

pub struct K8sTrafficLabeler {
    k8s_inquirer: Arc<dyn crate::k8s::K8sInquire + Send + Sync>,
}

pub struct TrafficLabeler {
    pub k8s_labeler: K8sTrafficLabeler,
}
