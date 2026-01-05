use anyhow::{Context, Result};
use api::{HttpMeta, L4Meta};
use async_trait::async_trait;
use futures::StreamExt;
use k8s_openapi::{
    api::core::v1::{Pod, Service},
    api::networking::v1::{Ingress, IngressRule},
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{
    Api, Client,
    runtime::{
        reflector::{self, Store},
        watcher,
    },
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct SvcMeta {
    pub namespace: String,
    pub service_name: String,
}
#[derive(Clone, Debug)]
pub struct PodMeta {
    pub namespace: String,
    pub pod_name: String,
}

#[derive(Default)]
struct PodIndex {
    by_ip: HashMap<String, PodMeta>,
}

#[derive(Default)]
struct ServiceIndex {
    // NodePort -> List of services (handling protocol collisions or same port multiple protocols)
    by_nodeport: HashMap<u16, Vec<ServicePortEntry>>,
}

#[derive(Clone)]
struct ServicePortEntry {
    protocol: String,
    meta: SvcMeta,
}

#[derive(Default)]
struct IngressIndex {
    // Host -> List of entries
    by_host: HashMap<String, Vec<IngressEntry>>,
}

#[derive(Clone)]
struct IngressEntry {
    ips: Vec<String>,
    service_name: String,
    namespace: String,
}

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

#[derive(Clone)]
pub struct K8sInquirer {
    // We keep stores to ensure reflector keeps them updated, though we use indexes for lookup.
    // The reflector stream drives the store update.
    _ingress_store: Store<Ingress>,
    _service_store: Store<Service>,
    _pod_store: Store<Pod>,

    ingress_index: Arc<RwLock<IngressIndex>>,
    service_index: Arc<RwLock<ServiceIndex>>,
    pod_index: Arc<RwLock<PodIndex>>,
}

impl K8sInquirer {
    pub async fn new() -> Result<Self> {
        Self::connect_default().await
    }

    pub async fn connect_default() -> Result<Self> {
        let client = Client::try_default()
            .await
            .context("constructing default kubernetes client")?;
        Self::with_client(client)
    }

    pub fn with_client(client: Client) -> Result<Self> {
        let ingress_api = Api::<Ingress>::all(client.clone());
        let service_api = Api::<Service>::all(client.clone());
        let pod_api = Api::<Pod>::all(client.clone());

        let (ingress_store, ingress_writer) = reflector::store();
        let (service_store, service_writer) = reflector::store();
        let (pod_store, pod_writer) = reflector::store();

        let ingress_index = Arc::new(RwLock::new(IngressIndex::default()));
        let service_index = Arc::new(RwLock::new(ServiceIndex::default()));
        let pod_index = Arc::new(RwLock::new(PodIndex::default()));

        // Ingress Watcher
        {
            let store = ingress_store.clone();
            let index = ingress_index.clone();
            tokio::spawn(async move {
                let mut stream = reflector::reflector(
                    ingress_writer,
                    watcher(ingress_api, watcher::Config::default()),
                )
                .boxed();
                while let Some(event) = stream.next().await {
                    if event.is_ok() {
                        rebuild_ingress_index(&store, &index);
                    }
                }
            });
        }

        // Service Watcher
        {
            let store = service_store.clone();
            let index = service_index.clone();
            tokio::spawn(async move {
                let mut stream = reflector::reflector(
                    service_writer,
                    watcher(service_api, watcher::Config::default()),
                )
                .boxed();
                while let Some(event) = stream.next().await {
                    if event.is_ok() {
                        rebuild_service_index(&store, &index);
                    }
                }
            });
        }

        // Pod Watcher
        {
            let store = pod_store.clone();
            let index = pod_index.clone();
            tokio::spawn(async move {
                let mut stream =
                    reflector::reflector(pod_writer, watcher(pod_api, watcher::Config::default()))
                        .boxed();
                while let Some(event) = stream.next().await {
                    if event.is_ok() {
                        rebuild_pod_index(&store, &index);
                    }
                }
            });
        }

        Ok(Self {
            _ingress_store: ingress_store,
            _service_store: service_store,
            _pod_store: pod_store,
            ingress_index,
            service_index,
            pod_index,
        })
    }
}

#[async_trait]
impl K8sInquire for K8sInquirer {
    async fn inquire_ingress(&self, http_meta: &HttpMeta) -> Result<Option<SvcMeta>> {
        if http_meta.host.is_empty() {
            return Ok(None);
        }
        let normalized_host = normalize_host(&http_meta.host);

        let index = self.ingress_index.read().unwrap();
        if let Some(entries) = index.by_host.get(&normalized_host) {
            for entry in entries {
                // Check IP match
                // If target_ip is empty, match. Else check if present.
                if http_meta.host_ip.is_empty()
                    || entry.ips.iter().any(|ip| ip == &http_meta.host_ip)
                {
                    return Ok(Some(SvcMeta {
                        namespace: entry.namespace.clone(),
                        service_name: entry.service_name.clone(),
                    }));
                }
            }
        }
        Ok(None)
    }

    async fn inquire_nodeport(&self, l4_meta: &L4Meta) -> Result<Option<SvcMeta>> {
        let index = self.service_index.read().unwrap();
        if let Some(entries) = index.by_nodeport.get(&l4_meta.local_port) {
            for entry in entries {
                if protocol_matches(&entry.protocol, l4_meta.protocol) {
                    return Ok(Some(entry.meta.clone()));
                }
            }
        }
        Ok(None)
    }

    async fn inquire_pod_to_world(&self, l4_meta: &L4Meta) -> Result<Option<PodMeta>> {
        let index = self.pod_index.read().unwrap();
        let local_ip = l4_meta.local_ip.to_string();
        if let Some(meta) = index.by_ip.get(&local_ip) {
            return Ok(Some(meta.clone()));
        }
        let remote_ip = l4_meta.remote_ip.to_string();
        if remote_ip != local_ip {
            if let Some(meta) = index.by_ip.get(&remote_ip) {
                return Ok(Some(meta.clone()));
            }
        }
        Ok(None)
    }
}

fn rebuild_ingress_index(store: &Store<Ingress>, index: &Arc<RwLock<IngressIndex>>) {
    let mut map: HashMap<String, Vec<IngressEntry>> = HashMap::new();
    for ingress in store.state() {
        let namespace = resource_namespace(&ingress.metadata);
        let ips = get_ingress_ips(&ingress);

        let Some(spec) = &ingress.spec else {
            continue;
        };
        let Some(rules) = &spec.rules else {
            continue;
        };
        for rule in rules {
            let Some(host) = &rule.host else {
                continue;
            };
            let Some(service_name) = first_backend_service_name(rule) else {
                continue;
            };

            let normalized = normalize_host(host);
            let entry = IngressEntry {
                ips: ips.clone(),
                namespace: namespace.clone(),
                service_name,
            };
            map.entry(normalized).or_default().push(entry);
        }
    }
    if let Ok(mut guard) = index.write() {
        guard.by_host = map;
    }
}

fn rebuild_service_index(store: &Store<Service>, index: &Arc<RwLock<ServiceIndex>>) {
    let mut map: HashMap<u16, Vec<ServicePortEntry>> = HashMap::new();
    for svc in store.state() {
        let Some(spec) = &svc.spec else {
            continue;
        };
        if !matches!(
            spec.type_.as_deref(),
            Some("NodePort") | Some("LoadBalancer")
        ) {
            continue;
        }
        let Some(ports) = &spec.ports else {
            continue;
        };
        let namespace = resource_namespace(&svc.metadata);
        let Some(service_name) = &svc.metadata.name else {
            continue;
        };
        for port in ports {
            let Some(node_port) = port.node_port else {
                continue;
            };
            let protocol = port.protocol.as_deref().unwrap_or("TCP").to_string();
            let entry = ServicePortEntry {
                protocol,
                meta: SvcMeta {
                    namespace: namespace.clone(),
                    service_name: service_name.clone(),
                },
            };
            map.entry(node_port as u16).or_default().push(entry);
        }
    }
    if let Ok(mut guard) = index.write() {
        guard.by_nodeport = map;
    }
}

fn rebuild_pod_index(store: &Store<Pod>, index: &Arc<RwLock<PodIndex>>) {
    let mut map = HashMap::new();
    for pod in store.state() {
        let Some(status) = &pod.status else {
            continue;
        };
        let Some(ip) = &status.pod_ip else {
            continue;
        };
        let Some(name) = &pod.metadata.name else {
            continue;
        };
        map.insert(
            ip.clone(),
            PodMeta {
                namespace: resource_namespace(&pod.metadata),
                pod_name: name.clone(),
            },
        );
    }
    if let Ok(mut guard) = index.write() {
        guard.by_ip = map;
    }
}

fn get_ingress_ips(ingress: &Ingress) -> Vec<String> {
    let mut ips = Vec::new();
    if let Some(status) = &ingress.status {
        if let Some(lb) = &status.load_balancer {
            if let Some(entries) = &lb.ingress {
                for entry in entries {
                    if let Some(ip) = &entry.ip {
                        ips.push(ip.clone());
                    }
                }
            }
        }
    }
    ips
}

fn protocol_matches(k8s_proto: &str, flow_proto: u8) -> bool {
    match (k8s_proto.to_uppercase().as_str(), flow_proto) {
        ("TCP", 6) => true,
        ("UDP", 17) => true,
        ("SCTP", 132) => true,
        _ => false,
    }
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
    nodeport_by_l4: HashMap<L4Meta, SvcMeta>,
    pod_to_world_by_l4: HashMap<L4Meta, PodMeta>,
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
        self.nodeport_by_l4.insert(*l4_meta, svc_meta);
    }

    pub fn register_pod_to_world(&mut self, l4_meta: &L4Meta, pod_meta: PodMeta) {
        self.pod_to_world_by_l4.insert(*l4_meta, pod_meta);
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
        Ok(self.nodeport_by_l4.get(l4_meta).cloned())
    }

    async fn inquire_pod_to_world(&self, l4_meta: &L4Meta) -> Result<Option<PodMeta>> {
        Ok(self.pod_to_world_by_l4.get(l4_meta).cloned())
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
        let l4_meta = L4Meta {
            local_ip: "10.0.0.2".parse()?,
            remote_ip: "52.52.52.52".parse()?,
            local_port: 32_000,
            remote_port: 443,
            protocol: 6,
        };
        dummy.register_nodeport(
            &l4_meta,
            SvcMeta {
                namespace: "payments".to_string(),
                service_name: "gateway".to_string(),
            },
        );

        let svc = dummy
            .inquire_nodeport(&l4_meta)
            .await?
            .expect("expected nodeport lookup to succeed");
        assert_eq!(svc.namespace, "payments");
        assert_eq!(svc.service_name, "gateway");
        Ok(())
    }

    #[tokio::test]
    async fn dummy_pod_lookup_returns_match() -> Result<()> {
        let mut dummy = DummyK8sInquirer::new();
        let l4_meta = L4Meta {
            local_ip: "172.16.0.10".parse()?,
            remote_ip: "8.8.8.8".parse()?,
            local_port: 8080,
            remote_port: 53,
            protocol: 17,
        };
        dummy.register_pod_to_world(
            &l4_meta,
            PodMeta {
                namespace: "observability".to_string(),
                pod_name: "pod-a".to_string(),
            },
        );

        let pod = dummy
            .inquire_pod_to_world(&l4_meta)
            .await?
            .expect("expected pod lookup to succeed");
        assert_eq!(pod.namespace, "observability");
        assert_eq!(pod.pod_name, "pod-a");
        Ok(())
    }
}
