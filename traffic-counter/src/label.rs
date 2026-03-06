use anyhow::Result;
use api::{ClusterTraffic, HttpGatewayTraffic, NodePortTraffic};
use async_trait::async_trait;
use std::fmt::Display;
use std::sync::Arc;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct ReservedPortLabel {
    pub port: u16,
    pub node_ip: String,
    // pub protocol: String,
}

impl Display for ReservedPortLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReservedPort({}:{})", self.node_ip, self.port)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct K8sNodePortLabel {
    pub namespace: String,
    pub service_name: String,
    pub port: u16,
    pub node_ip: String,
    // pub port_name: String,
    // pub port_protocol: String,
    // pub node_port: u16,
}

impl Display for K8sNodePortLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "K8sNodePort(namespace: {}, service: {}, port: {}, node_ip: {})",
            self.namespace, self.service_name, self.port, self.node_ip
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct DynamicPortLabel {
    pub port: u16,
    pub node_ip: String,
    // pub protocol: String,
}

impl Display for DynamicPortLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DynamicPort({}:{})", self.node_ip, self.port)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NodePortLabel {
    Reserved(ReservedPortLabel),
    K8sNode(K8sNodePortLabel),
    Dynamic(DynamicPortLabel),
}

impl Display for NodePortLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodePortLabel::Reserved(label) => write!(f, "{}", label),
            NodePortLabel::K8sNode(label) => write!(f, "{}", label),
            NodePortLabel::Dynamic(label) => write!(f, "{}", label),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct K8sPodLabel {
    pub namespace: String,
    pub pod_name: String,
}

impl Display for K8sPodLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "K8sPod(namespace: {}, pod: {})",
            self.namespace, self.pod_name
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ClusterLabel {
    K8sPod(K8sPodLabel),
}

impl Display for ClusterLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterLabel::K8sPod(label) => write!(f, "{}", label),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct K8sIngressLabel {
    pub namespace: String,
    pub service_name: String,
    pub host: String,
    // pub path: String,
}

impl Display for K8sIngressLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "K8sIngress(namespace: {}, service: {}, host: {})",
            self.namespace, self.service_name, self.host
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum HttpGatewayLabel {
    K8sIngress(K8sIngressLabel),
}

impl Display for HttpGatewayLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpGatewayLabel::K8sIngress(label) => write!(f, "{}", label),
        }
    }
}

pub enum Label {
    NodePort(NodePortLabel),
    HttpGateway(HttpGatewayLabel),
    Cluster(ClusterLabel),
}

impl Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Label::NodePort(label) => write!(f, "{}", label),
            Label::HttpGateway(label) => write!(f, "{}", label),
            Label::Cluster(label) => write!(f, "{}", label),
        }
    }
}

#[async_trait]
pub trait TrafficLabel<T, L>: Send + Sync
where
    T: Send + 'static,
{
    async fn label(&self, traffic: &T) -> Result<Option<L>>;
}

#[async_trait]
impl TrafficLabel<HttpGatewayTraffic, HttpGatewayLabel> for K8sTrafficLabeler {
    async fn label(&self, traffic: &HttpGatewayTraffic) -> Result<Option<HttpGatewayLabel>> {
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
            host: traffic.http_meta.host.clone(),
        });
        Ok(Some(l))
    }
}

#[async_trait]
impl TrafficLabel<HttpGatewayTraffic, HttpGatewayLabel> for TrafficLabeler {
    async fn label(&self, traffic: &HttpGatewayTraffic) -> Result<Option<HttpGatewayLabel>> {
        self.k8s_labeler.label(traffic).await
    }
}

#[async_trait]
impl TrafficLabel<NodePortTraffic, NodePortLabel> for K8sTrafficLabeler {
    async fn label(&self, traffic: &NodePortTraffic) -> Result<Option<NodePortLabel>> {
        let result = self.k8s_inquirer.inquire_nodeport(&traffic.l4_meta).await?;
        let Some(svc_meta) = result else {
            return Ok(None);
        };
        let l = NodePortLabel::K8sNode(K8sNodePortLabel {
            namespace: svc_meta.namespace,
            service_name: svc_meta.service_name,
            port: traffic.l4_meta.local_port,
            node_ip: traffic.l4_meta.local_ip.to_string(),
        });
        Ok(Some(l))
    }
}

#[async_trait]
impl TrafficLabel<NodePortTraffic, NodePortLabel> for TrafficLabeler {
    async fn label(&self, traffic: &NodePortTraffic) -> Result<Option<NodePortLabel>> {
        if let Some(k8s_nodeport_label) = self.k8s_labeler.label(traffic).await? {
            return Ok(Some(k8s_nodeport_label));
        }
        // Fallback to other labeling strategies here if needed
        if traffic.l4_meta.local_port < 1024 {
            Ok(Some(NodePortLabel::Reserved(ReservedPortLabel {
                port: traffic.l4_meta.local_port,
                node_ip: traffic.l4_meta.local_ip.to_string(),
            })))
        } else {
            Ok(Some(NodePortLabel::Dynamic(DynamicPortLabel {
                port: traffic.l4_meta.local_port,
                node_ip: traffic.l4_meta.local_ip.to_string(),
            })))
        }
    }
}

#[async_trait]
impl TrafficLabel<ClusterTraffic, ClusterLabel> for K8sTrafficLabeler {
    async fn label(&self, traffic: &ClusterTraffic) -> Result<Option<ClusterLabel>> {
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

#[async_trait]
impl TrafficLabel<ClusterTraffic, ClusterLabel> for TrafficLabeler {
    async fn label(&self, traffic: &ClusterTraffic) -> Result<Option<ClusterLabel>> {
        self.k8s_labeler.label(traffic).await
    }
}

pub struct K8sTrafficLabeler {
    k8s_inquirer: Arc<dyn crate::k8s::K8sInquire + Send + Sync>,
}

impl K8sTrafficLabeler {
    pub fn new(k8s_inquirer: Arc<dyn crate::k8s::K8sInquire + Send + Sync>) -> Self {
        Self { k8s_inquirer }
    }
}

pub struct TrafficLabeler {
    pub k8s_labeler: K8sTrafficLabeler,
}

impl TrafficLabeler {
    pub fn new(k8s_labeler: K8sTrafficLabeler) -> Self {
        Self { k8s_labeler }
    }
}
