use crate::traffic::{HttpMeta, L4Meta, PodMeta, SvcMeta};
use anyhow::{Context, Result};
use async_trait::async_trait;
use k8s_openapi::{
    api::core::v1::{Pod, Service},
    api::networking::v1::{Ingress, IngressRule, IngressStatus},
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{Api, Client, api::ListParams};
use std::collections::HashMap;

#[async_trait]
pub trait K8sInquire: Send + Sync {
    async fn inquire_ingress(&self, _http_meta: &HttpMeta) -> Result<Option<SvcMeta>> {
        Ok(None)
    }
    async fn inquire_nodeport(&self, _l4_meta: &L4Meta) -> Result<Option<SvcMeta>> {
        Ok(None)
    }
    async fn inquire_pod_to_world(&self, _l4_meta: &L4Meta) -> Result<Option<PodMeta>> {
        Ok(None)
    }
}

pub struct K8sInquirer {
    client: Client,
}

impl K8sInquirer {
    pub async fn new() -> Result<Self> {
        Self::connect_default().await
    }

    pub async fn connect_default() -> Result<Self> {
        let client = Client::try_default()
            .await
            .context("constructing default kubernetes client")?;
        Ok(Self { client })
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl K8sInquire for K8sInquirer {
    async fn inquire_ingress(&self, http_meta: &HttpMeta) -> Result<Option<SvcMeta>> {
        let client = self.client.clone();
        lookup_ingress(client, http_meta.clone()).await
    }

    async fn inquire_nodeport(&self, l4_meta: &L4Meta) -> Result<Option<SvcMeta>> {
        let client = self.client.clone();
        lookup_nodeport(client, l4_meta.clone()).await
    }

    async fn inquire_pod_to_world(&self, l4_meta: &L4Meta) -> Result<Option<PodMeta>> {
        let client = self.client.clone();
        lookup_pod_for_l4(client, l4_meta.clone()).await
    }
}

async fn lookup_ingress(client: Client, http: HttpMeta) -> Result<Option<SvcMeta>> {
    if http.host.is_empty() {
        return Ok(None);
    }

    let normalized_host = normalize_host(&http.host);
    let ingresses: Api<Ingress> = Api::all(client);
    let ingress_list = ingresses
        .list(&ListParams::default())
        .await
        .with_context(|| format!("listing ingress resources for host {}", normalized_host))?;

    for ingress in ingress_list.items {
        if !ingress_status_matches_ip(ingress.status.as_ref(), &http.host_ip) {
            continue;
        }

        let namespace = resource_namespace(&ingress.metadata);
        let Some(spec) = ingress.spec else {
            continue;
        };
        let rules = spec.rules.unwrap_or_default();
        for rule in &rules {
            if !ingress_rule_matches_host(rule, &normalized_host) {
                continue;
            }
            if let Some(service_name) = first_backend_service_name(rule) {
                return Ok(Some(SvcMeta {
                    namespace: namespace.clone(),
                    service_name,
                }));
            }
        }
    }

    Ok(None)
}

async fn lookup_nodeport(client: Client, l4: L4Meta) -> Result<Option<SvcMeta>> {
    let services: Api<Service> = Api::all(client);
    let svc_list = services
        .list(&ListParams::default())
        .await
        .context("listing services for nodeport lookup")?;

    for svc in svc_list.items {
        let Some(spec) = svc.spec else {
            continue;
        };
        if !matches!(
            spec.type_.as_deref(),
            Some("NodePort") | Some("LoadBalancer")
        ) {
            continue;
        }
        let ports = spec.ports.unwrap_or_default();
        for port in ports {
            let Some(node_port) = port.node_port else {
                continue;
            };
            if (node_port as u16) != l4.local_port {
                continue;
            }
            let protocol = port.protocol.as_deref().unwrap_or("TCP");
            if !protocol.eq_ignore_ascii_case(&l4.protocol) {
                continue;
            }
            let Some(service_name) = svc.metadata.name.clone() else {
                continue;
            };
            return Ok(Some(SvcMeta {
                namespace: resource_namespace(&svc.metadata),
                service_name,
            }));
        }
    }

    Ok(None)
}

async fn lookup_pod_for_l4(client: Client, l4: L4Meta) -> Result<Option<PodMeta>> {
    let local_ip = l4.local_ip.clone();
    if let Some(pod_meta) = query_pod_by_ip(client.clone(), local_ip.clone()).await? {
        return Ok(Some(pod_meta));
    }
    let remote_ip = l4.remote_ip.clone();
    if remote_ip.is_empty() || remote_ip == local_ip {
        return Ok(None);
    }
    query_pod_by_ip(client, remote_ip).await
}

async fn query_pod_by_ip(client: Client, ip: String) -> Result<Option<PodMeta>> {
    if ip.is_empty() {
        return Ok(None);
    }

    let pods: Api<Pod> = Api::all(client);
    let params = ListParams {
        field_selector: Some(format!("status.podIP={ip}")),
        ..Default::default()
    };
    let pod_list = pods
        .list(&params)
        .await
        .with_context(|| format!("listing pods for ip {}", ip))?;

    for pod in pod_list.items {
        let matches_ip = pod
            .status
            .as_ref()
            .and_then(|status| status.pod_ip.as_ref())
            .map(|pod_ip| pod_ip == &ip)
            .unwrap_or(false);
        if !matches_ip {
            continue;
        }
        let Some(pod_name) = pod.metadata.name.clone() else {
            continue;
        };
        return Ok(Some(PodMeta {
            namespace: resource_namespace(&pod.metadata),
            pod_name,
        }));
    }

    Ok(None)
}

fn ingress_status_matches_ip(status: Option<&IngressStatus>, target_ip: &str) -> bool {
    if target_ip.is_empty() {
        return true;
    }

    status
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.ip.as_ref())
                .any(|ip| ip == target_ip)
        })
        .unwrap_or(false)
}

fn ingress_rule_matches_host(rule: &IngressRule, normalized_host: &str) -> bool {
    if normalized_host.is_empty() {
        return false;
    }

    rule.host
        .as_deref()
        .map(|host| normalize_host(host) == normalized_host)
        .unwrap_or(false)
}

fn first_backend_service_name(rule: &IngressRule) -> Option<String> {
    let http = rule.http.as_ref()?;
    for path in &http.paths {
        if let Some(service) = path.backend.service.as_ref() {
            return Some(service.name.clone());
        }
    }
    None
}

fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn resource_namespace(meta: &ObjectMeta) -> String {
    meta.namespace
        .clone()
        .unwrap_or_else(|| "default".to_string())
}

#[derive(Default)]
pub struct DummyK8sInquirer {
    ingress_by_http: HashMap<IngressKey, SvcMeta>,
    nodeport_by_l4: HashMap<L4Key, SvcMeta>,
    pod_to_world_by_l4: HashMap<L4Key, PodMeta>,
}

impl DummyK8sInquirer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_ingress(&mut self, http_meta: &HttpMeta, svc_meta: SvcMeta) {
        self.ingress_by_http
            .insert(IngressKey::from(http_meta), svc_meta);
    }

    pub fn register_nodeport(&mut self, l4_meta: &L4Meta, svc_meta: SvcMeta) {
        self.nodeport_by_l4.insert(L4Key::from(l4_meta), svc_meta);
    }

    pub fn register_pod_to_world(&mut self, l4_meta: &L4Meta, pod_meta: PodMeta) {
        self.pod_to_world_by_l4
            .insert(L4Key::from(l4_meta), pod_meta);
    }
}

#[async_trait]
impl K8sInquire for DummyK8sInquirer {
    async fn inquire_ingress(&self, http_meta: &HttpMeta) -> Result<Option<SvcMeta>> {
        Ok(self
            .ingress_by_http
            .get(&IngressKey::from(http_meta))
            .cloned())
    }

    async fn inquire_nodeport(&self, l4_meta: &L4Meta) -> Result<Option<SvcMeta>> {
        Ok(self.nodeport_by_l4.get(&L4Key::from(l4_meta)).cloned())
    }

    async fn inquire_pod_to_world(&self, l4_meta: &L4Meta) -> Result<Option<PodMeta>> {
        Ok(self.pod_to_world_by_l4.get(&L4Key::from(l4_meta)).cloned())
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct IngressKey {
    host_ip: String,
    client_ip: String,
    host: String,
}

impl From<&HttpMeta> for IngressKey {
    fn from(meta: &HttpMeta) -> Self {
        Self {
            host_ip: meta.host_ip.clone(),
            client_ip: meta.client_ip.clone(),
            host: meta.host.clone(),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct L4Key {
    local_ip: String,
    remote_ip: String,
    local_port: u16,
    remote_port: u16,
    protocol: String,
}

impl From<&L4Meta> for L4Key {
    fn from(meta: &L4Meta) -> Self {
        Self {
            local_ip: meta.local_ip.clone(),
            remote_ip: meta.remote_ip.clone(),
            local_port: meta.local_port,
            remote_port: meta.remote_port,
            protocol: meta.protocol.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn dummy_ingress_lookup_returns_match() -> Result<()> {
        let mut dummy = DummyK8sInquirer::new();
        let http = HttpMeta {
            host_ip: "10.0.0.1".to_string(),
            client_ip: "192.168.1.5".to_string(),
            host: "demo.example.com".to_string(),
        };
        dummy.register_ingress(
            &http,
            SvcMeta {
                namespace: "demo".to_string(),
                service_name: "web".to_string(),
            },
        );

        let svc = dummy
            .inquire_ingress(&http)
            .await?
            .expect("expected ingress lookup to succeed");
        assert_eq!(svc.namespace, "demo");
        assert_eq!(svc.service_name, "web");
        Ok(())
    }

    #[tokio::test]
    async fn dummy_nodeport_lookup_returns_match() -> Result<()> {
        let mut dummy = DummyK8sInquirer::new();
        let l4 = L4Meta {
            local_ip: "10.0.0.2".to_string(),
            remote_ip: "52.52.52.52".to_string(),
            local_port: 32_000,
            remote_port: 443,
            protocol: "TCP".to_string(),
        };
        dummy.register_nodeport(
            &l4,
            SvcMeta {
                namespace: "payments".to_string(),
                service_name: "gateway".to_string(),
            },
        );

        let svc = dummy
            .inquire_nodeport(&l4)
            .await?
            .expect("expected nodeport lookup to succeed");
        assert_eq!(svc.namespace, "payments");
        assert_eq!(svc.service_name, "gateway");
        Ok(())
    }

    #[tokio::test]
    async fn dummy_pod_lookup_returns_match() -> Result<()> {
        let mut dummy = DummyK8sInquirer::new();
        let l4 = L4Meta {
            local_ip: "172.16.0.10".to_string(),
            remote_ip: "8.8.8.8".to_string(),
            local_port: 8080,
            remote_port: 53,
            protocol: "UDP".to_string(),
        };
        dummy.register_pod_to_world(
            &l4,
            PodMeta {
                namespace: "observability".to_string(),
                pod_name: "pod-a".to_string(),
            },
        );

        let pod = dummy
            .inquire_pod_to_world(&l4)
            .await?
            .expect("expected pod lookup to succeed");
        assert_eq!(pod.namespace, "observability");
        assert_eq!(pod.pod_name, "pod-a");
        Ok(())
    }
}
