use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use api::Traffic;
use base64::{Engine as _, engine::general_purpose};
use clap::{Args, ValueEnum};
use hyper::{
    Body, Request, Response, Server, StatusCode,
    header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE},
    service::{make_service_fn, service_fn},
};
use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder};
use tokio::{sync::Mutex, task::JoinHandle, time};
use tracing::{error, info};

use crate::{
    label::{ClusterLabel, HttpGatewayLabel, Label, NodePortLabel},
    store::TrafficDump,
};

/// Trait representing anything that can export itself into another form.
pub trait Export: Send + Sync {
    /// Perform the export and return the resulting value.
    async fn run(&self, running: Arc<AtomicBool>, interval: Duration, natural: bool) -> Result<()>;
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ExportMode {
    Log,
    Prometheus,
}
#[derive(Args)]
pub struct ExportConfig {
    /// Export interval in seconds
    #[arg(long, default_value = "5")]
    pub export_interval_secs: u64,

    /// Exporter backend to use
    #[arg(long, value_enum, default_value = "log")]
    pub export_mode: ExportMode,

    /// Address for the Prometheus exporter to listen on
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub prometheus_listen_addr: SocketAddr,

    /// Whether to export receive-side metrics (bytes/packets)
    #[arg(long, default_value_t = true)]
    pub export_rx_metrics: bool,

    /// Whether to export transmit-side metrics (bytes/packets)
    #[arg(long, default_value_t = true)]
    pub export_tx_metrics: bool,

    /// Username required to access the Prometheus metrics endpoint
    #[arg(
        long,
        env = "PROMETHEUS_METRICS_USERNAME",
        requires = "metrics_password"
    )]
    pub metrics_username: Option<String>,

    /// Password required to access the Prometheus metrics endpoint
    #[arg(
        long,
        env = "PROMETHEUS_METRICS_PASSWORD",
        requires = "metrics_username"
    )]
    pub metrics_password: Option<String>,
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
            let records = self.traffic_dumper.dump();
            for (label, value) in records {
                info!("Exported Record: {} => {}", label, value);
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
            let records = self.traffic_dumper.dump();
            for (label, value) in records {
                info!("Exported Record: {} => {}", label, value);
            }
        }
        Ok(())
    }
}

const PROM_LABEL_DIMENSIONS: [&str; 6] = [
    "type",
    "namespace",
    "service_name",
    "pod_name",
    "host",
    "port",
];
const PROM_LABEL_DIMENSION_COUNT: usize = PROM_LABEL_DIMENSIONS.len();

#[derive(Clone, Debug)]
struct MetricsAuth {
    username: String,
    password: String,
}

pub struct PrometheusExporter {
    traffic_dumper: Arc<dyn TrafficDump>,
    registry: Registry,
    nodeport_rx_bytes: IntCounterVec,
    nodeport_rx_packets: IntCounterVec,
    nodeport_tx_bytes: IntCounterVec,
    nodeport_tx_packets: IntCounterVec,
    cluster_rx_bytes: IntCounterVec,
    cluster_rx_packets: IntCounterVec,
    cluster_tx_bytes: IntCounterVec,
    cluster_tx_packets: IntCounterVec,
    http_request_bytes: IntCounterVec,
    http_response_bytes: IntCounterVec,
    export_rx_metrics: bool,
    export_tx_metrics: bool,
    http_addr: SocketAddr,
    metrics_auth: Option<MetricsAuth>,
    server_task: Mutex<Option<JoinHandle<()>>>,
}

impl Export for PrometheusExporter {
    async fn run(&self, running: Arc<AtomicBool>, interval: Duration, natural: bool) -> Result<()> {
        self.ensure_server().await;
        if natural {
            self.run_at_natural_interval(running, interval).await
        } else {
            self.run_at_interval(running, interval).await
        }
    }
}

impl PrometheusExporter {
    pub fn new(
        traffic_dumper: Arc<dyn TrafficDump>,
        http_addr: SocketAddr,
        export_rx_metrics: bool,
        export_tx_metrics: bool,
        metrics_auth: Option<(String, String)>,
    ) -> Result<Self> {
        let registry = Registry::new();
        let nodeport_rx_bytes = Self::register_counter(
            &registry,
            "traffic_nodeport_rx_bytes_total",
            "Total received bytes observed for nodeport traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let nodeport_rx_packets = Self::register_counter(
            &registry,
            "traffic_nodeport_rx_packets_total",
            "Total received packets observed for nodeport traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let nodeport_tx_bytes = Self::register_counter(
            &registry,
            "traffic_nodeport_tx_bytes_total",
            "Total transmitted bytes observed for nodeport traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let nodeport_tx_packets = Self::register_counter(
            &registry,
            "traffic_nodeport_tx_packets_total",
            "Total transmitted packets observed for nodeport traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let cluster_rx_bytes = Self::register_counter(
            &registry,
            "traffic_cluster_rx_bytes_total",
            "Total received bytes observed for cluster traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let cluster_rx_packets = Self::register_counter(
            &registry,
            "traffic_cluster_rx_packets_total",
            "Total received packets observed for cluster traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let cluster_tx_bytes = Self::register_counter(
            &registry,
            "traffic_cluster_tx_bytes_total",
            "Total transmitted bytes observed for cluster traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let cluster_tx_packets = Self::register_counter(
            &registry,
            "traffic_cluster_tx_packets_total",
            "Total transmitted packets observed for cluster traffic",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let http_request_bytes = Self::register_counter(
            &registry,
            "traffic_http_request_bytes_total",
            "Total HTTP request bytes observed at the gateway",
            &PROM_LABEL_DIMENSIONS,
        )?;
        let http_response_bytes = Self::register_counter(
            &registry,
            "traffic_http_response_bytes_total",
            "Total HTTP response bytes observed at the gateway",
            &PROM_LABEL_DIMENSIONS,
        )?;

        let metrics_auth =
            metrics_auth.map(|(username, password)| MetricsAuth { username, password });

        Ok(Self {
            traffic_dumper,
            registry,
            nodeport_rx_bytes,
            nodeport_rx_packets,
            nodeport_tx_bytes,
            nodeport_tx_packets,
            cluster_rx_bytes,
            cluster_rx_packets,
            cluster_tx_bytes,
            cluster_tx_packets,
            http_request_bytes,
            http_response_bytes,
            export_rx_metrics,
            export_tx_metrics,
            http_addr,
            metrics_auth,
            server_task: Mutex::new(None),
        })
    }

    async fn ensure_server(&self) {
        let mut guard = self.server_task.lock().await;
        if guard.is_some() {
            return;
        }

        let registry = self.registry.clone();
        let addr = self.http_addr;
        let metrics_auth = self.metrics_auth.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = Self::serve_metrics(registry, addr, metrics_auth).await {
                error!(%addr, "Prometheus metrics server terminated: {err:?}");
            }
        });
        *guard = Some(handle);
    }

    async fn run_at_interval(&self, running: Arc<AtomicBool>, interval: Duration) -> Result<()> {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            if !running.load(Ordering::Relaxed) {
                break;
            }
            self.export_once()?;
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
            self.export_once()?;
        }
        Ok(())
    }

    fn export_once(&self) -> Result<()> {
        let records = self.traffic_dumper.dump();
        if records.is_empty() {
            return Ok(());
        }
        self.observe_records(records);
        Ok(())
    }

    fn observe_records(&self, records: Vec<(Label, Traffic)>) {
        for (label, traffic) in records {
            let label_values = Self::build_label_values(&label);
            let label_refs: Vec<&str> = label_values.iter().map(|s| s.as_str()).collect();
            match traffic {
                Traffic::NodePort(data) => {
                    if self.export_rx_metrics {
                        self.nodeport_rx_bytes
                            .with_label_values(&label_refs)
                            .inc_by(data.rx_bytes);
                        self.nodeport_rx_packets
                            .with_label_values(&label_refs)
                            .inc_by(data.rx_packets);
                    }
                    if self.export_tx_metrics {
                        self.nodeport_tx_bytes
                            .with_label_values(&label_refs)
                            .inc_by(data.tx_bytes);
                        self.nodeport_tx_packets
                            .with_label_values(&label_refs)
                            .inc_by(data.tx_packets);
                    }
                }
                Traffic::HttpGateway(data) => {
                    if self.export_rx_metrics {
                        self.http_request_bytes
                            .with_label_values(&label_refs)
                            .inc_by(data.request_bytes);
                    }
                    if self.export_tx_metrics {
                        self.http_response_bytes
                            .with_label_values(&label_refs)
                            .inc_by(data.response_bytes);
                    }
                }
                Traffic::Cluster(data) => {
                    if self.export_rx_metrics {
                        self.cluster_rx_bytes
                            .with_label_values(&label_refs)
                            .inc_by(data.rx_bytes);
                        self.cluster_rx_packets
                            .with_label_values(&label_refs)
                            .inc_by(data.rx_packets);
                    }
                    if self.export_tx_metrics {
                        self.cluster_tx_bytes
                            .with_label_values(&label_refs)
                            .inc_by(data.tx_bytes);
                        self.cluster_tx_packets
                            .with_label_values(&label_refs)
                            .inc_by(data.tx_packets);
                    }
                }
            }
        }
    }

    fn register_counter(
        registry: &Registry,
        name: &str,
        help: &str,
        label_names: &[&str],
    ) -> Result<IntCounterVec> {
        let counter = IntCounterVec::new(Opts::new(name, help), label_names)?;
        registry.register(Box::new(counter.clone()))?;
        Ok(counter)
    }

    fn build_label_values(label: &Label) -> [String; PROM_LABEL_DIMENSION_COUNT] {
        let mut values = [
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ];

        match label {
            Label::NodePort(node_label) => match node_label {
                NodePortLabel::Reserved(reserved) => {
                    values[0] = "nodeport_reserved".into();
                    values[5] = reserved.port.to_string();
                }
                NodePortLabel::Dynamic(dynamic) => {
                    values[0] = "nodeport_dynamic".into();
                    values[5] = dynamic.port.to_string();
                }
                NodePortLabel::K8sNode(k8s) => {
                    values[0] = "nodeport_k8s_node".into();
                    values[1] = k8s.namespace.clone();
                    values[2] = k8s.service_name.clone();
                }
            },
            Label::HttpGateway(gateway_label) => match gateway_label {
                HttpGatewayLabel::K8sIngress(ingress) => {
                    values[0] = "httpgateway_k8s_ingress".into();
                    values[1] = ingress.namespace.clone();
                    values[2] = ingress.service_name.clone();
                    values[4] = ingress.host.clone();
                }
            },
            Label::Cluster(cluster_label) => match cluster_label {
                ClusterLabel::K8sPod(pod) => {
                    values[0] = "cluster_k8s_pod".into();
                    values[1] = pod.namespace.clone();
                    values[3] = pod.pod_name.clone();
                }
            },
        }

        values
    }

    async fn serve_metrics(
        registry: Registry,
        addr: SocketAddr,
        metrics_auth: Option<MetricsAuth>,
    ) -> Result<()> {
        let metrics_auth = metrics_auth.clone();
        let make_service = make_service_fn(move |_| {
            let registry = registry.clone();
            let metrics_auth = metrics_auth.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let registry = registry.clone();
                    let metrics_auth = metrics_auth.clone();
                    async move {
                        Ok::<_, hyper::Error>(
                            Self::build_metrics_response(registry, req, metrics_auth).await,
                        )
                    }
                }))
            }
        });

        info!(%addr, "Prometheus metrics server listening");
        Server::bind(&addr).serve(make_service).await?;
        Ok(())
    }

    async fn build_metrics_response(
        registry: Registry,
        req: Request<Body>,
        metrics_auth: Option<MetricsAuth>,
    ) -> Response<Body> {
        if req.uri().path() != "/metrics" {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("not found"))
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }

        if let Some(auth) = metrics_auth.as_ref() {
            if let Err(response) = Self::validate_basic_auth(&req, auth) {
                return response;
            }
        }

        let encoder = TextEncoder::new();
        let metric_families = registry.gather();
        let mut buffer = Vec::new();
        let status = match encoder.encode(&metric_families, &mut buffer) {
            Ok(()) => StatusCode::OK,
            Err(err) => {
                buffer = format!("failed to encode metrics: {err}").into_bytes();
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, encoder.format_type())
            .body(Body::from(buffer))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("internal error"))
                    .expect("failed to build fallback response")
            })
    }

    fn validate_basic_auth(req: &Request<Body>, auth: &MetricsAuth) -> Result<(), Response<Body>> {
        let header_value = match req.headers().get(AUTHORIZATION) {
            Some(value) => value,
            None => return Err(Self::unauthorized_response()),
        };

        let header_str = match header_value.to_str() {
            Ok(value) => value.trim(),
            Err(_) => return Err(Self::unauthorized_response()),
        };

        let mut parts = header_str.splitn(2, ' ');
        let scheme = parts.next().unwrap_or("");
        let encoded = parts.next().unwrap_or("");

        if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
            return Err(Self::unauthorized_response());
        }

        let decoded = match general_purpose::STANDARD.decode(encoded) {
            Ok(bytes) => bytes,
            Err(_) => return Err(Self::unauthorized_response()),
        };

        let decoded_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return Err(Self::unauthorized_response()),
        };

        let mut credentials = decoded_str.splitn(2, ':');
        let username = credentials.next().unwrap_or("");
        let password = credentials.next().unwrap_or("");

        if username == auth.username && password == auth.password {
            Ok(())
        } else {
            Err(Self::unauthorized_response())
        }
    }

    fn unauthorized_response() -> Response<Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(WWW_AUTHENTICATE, r#"Basic realm="metrics""#)
            .body(Body::from("unauthorized"))
            .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
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
