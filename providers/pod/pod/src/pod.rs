use anyhow::{Context, Result, anyhow};
use api::proto::trafficcounter::v1::{
    IngestTrafficRequest, traffic_ingestor_client::TrafficIngestorClient,
};
use api::{ClusterTraffic, L4Meta, Traffic};
use aya::maps::{perf::PerfEventArray, ring_buf::RingBuf};
use aya::programs::SchedClassifier;
use aya::util::online_cpus;
use bytes::BytesMut;
use pod_provider_common::{Direction, Event};
use std::convert::TryFrom;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;

use crate::ebpf::EbpfManager;
use crate::netns::{NetnsGuard, current_netns_has_eth0, discover_pod_netns};
use crate::probe::probe_memcg_based_accounting_support;
use crate::probe::{probe_perf_event_array_support, probe_ringbuf_support};
pub struct PodOptions {
    pub config: PodConfig,
}
pub struct PodConfig {
    pub server_addr: String,
    pub workers: usize,
}

pub struct PodRuntime {
    pub config: PodConfig,
}

fn get_tc_program<'a>(
    ebpf: &'a mut aya::Ebpf,
    program_name: &str,
    label: &str,
) -> Result<&'a mut SchedClassifier> {
    ebpf.program_mut(program_name)
        .with_context(|| format!("missing {label} tc program"))?
        .try_into()
        .with_context(|| format!("convert {label} program to tc classifier"))
}

fn load_tc_programs(
    manager: &EbpfManager,
    ebpf: &mut aya::Ebpf,
    ingress_prog_name: &str,
    egress_prog_name: &str,
) -> Result<()> {
    {
        let ingress_prog = get_tc_program(ebpf, ingress_prog_name, "ingress")?;
        manager.load_program(ingress_prog)?;
    }
    {
        let egress_prog = get_tc_program(ebpf, egress_prog_name, "egress")?;
        manager.load_program(egress_prog)?;
    }
    Ok(())
}

fn attach_tc_programs(
    manager: &EbpfManager,
    ebpf: &mut aya::Ebpf,
    ingress_prog_name: &str,
    egress_prog_name: &str,
    iface: &str,
) -> Result<()> {
    {
        let ingress_prog = get_tc_program(ebpf, ingress_prog_name, "ingress")?;
        manager.attach(ingress_prog, iface, Direction::Ingress)?;
    }
    {
        let egress_prog = get_tc_program(ebpf, egress_prog_name, "egress")?;
        manager.attach(egress_prog, iface, Direction::Egress)?;
    }
    Ok(())
}

const RINGBUF_MAP_NAME: &str = "EVENTS";
const PERF_EVENT_MAP_NAME: &str = "EVENTS_LEGACY";

fn parse_event(source: &str, data: &[u8]) -> Option<Event> {
    if data.len() < size_of::<Event>() {
        warn!(
            source,
            data_len = data.len(),
            expected_len = size_of::<Event>(),
            "event buffer too small"
        );
        return None;
    }
    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
    Some(event)
}

fn ipv6_from_words(words: [u32; 4]) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    Ipv6Addr::from(bytes)
}

fn event_to_cluster_traffic(source: &str, event: &Event) -> Option<ClusterTraffic> {
    let protocol = match u8::try_from(event.protocol) {
        Ok(value) => value,
        Err(_) => {
            warn!(source, value = event.protocol, "protocol out of range");
            return None;
        }
    };
    let local_port = match u16::try_from(event.local_port) {
        Ok(value) => value,
        Err(_) => {
            warn!(source, value = event.local_port, "local port out of range");
            return None;
        }
    };
    let remote_port = match u16::try_from(event.remote_port) {
        Ok(value) => value,
        Err(_) => {
            warn!(
                source,
                value = event.remote_port,
                "remote port out of range"
            );
            return None;
        }
    };

    let (local_ip, remote_ip) = match event.family {
        family if family == libc::AF_INET as u32 => (
            IpAddr::V4(Ipv4Addr::from(event.local_ipv4)),
            IpAddr::V4(Ipv4Addr::from(event.remote_ipv4)),
        ),
        family if family == libc::AF_INET6 as u32 => (
            IpAddr::V6(ipv6_from_words(event.local_ipv6)),
            IpAddr::V6(ipv6_from_words(event.remote_ipv6)),
        ),
        _ => {
            warn!(source, family = event.family, "unsupported address family");
            return None;
        }
    };

    let (rx_bytes, rx_packets, tx_bytes, tx_packets) = match event.direction {
        direction if direction == Direction::Ingress as u32 => (event.len as u64, 1, 0, 0),
        direction if direction == Direction::Egress as u32 => (0, 0, event.len as u64, 1),
        _ => {
            warn!(source, direction = event.direction, "unknown direction");
            return None;
        }
    };

    Some(ClusterTraffic {
        l4_meta: L4Meta {
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            protocol,
        },
        rx_bytes,
        rx_packets,
        tx_bytes,
        tx_packets,
    })
}

fn event_to_ingest_request(source: &str, event: &Event) -> Option<IngestTrafficRequest> {
    let traffic = event_to_cluster_traffic(source, event)?;
    Some(IngestTrafficRequest {
        traffic: Some(Traffic::Cluster(traffic).into()),
    })
}

async fn run_grpc_manager(
    client: TrafficIngestorClient<Channel>,
    mut stable_rx: mpsc::Receiver<IngestTrafficRequest>,
) {
    let client = client;
    loop {
        let (stream_tx, stream_rx) = mpsc::channel(1024);
        let request_stream = ReceiverStream::new(stream_rx);

        let mut client_clone = client.clone();
        let grpc_handle =
            tokio::task::spawn(async move { client_clone.ingest_traffic(request_stream).await });

        loop {
            let req = match stable_rx.recv().await {
                Some(req) => req,
                None => return,
            };

            if stream_tx.send(req).await.is_err() {
                warn!("gRPC stream broken, reconnecting");
                break;
            }
        }

        let _ = grpc_handle.await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn spawn_ringbuf_consumer(
    ebpf: &mut aya::Ebpf,
    sender: mpsc::Sender<IngestTrafficRequest>,
) -> Result<()> {
    let map = ebpf
        .take_map(RINGBUF_MAP_NAME)
        .ok_or_else(|| anyhow!(format!("ringbuf {} not found", RINGBUF_MAP_NAME)))?;
    let ringbuf = RingBuf::try_from(map)
        .map_err(|err| anyhow!(format!("failed to create ringbuf: {err:?}")))?;
    let async_fd = AsyncFd::new(ringbuf)?;
    tokio::task::spawn(async move {
        let mut async_fd = async_fd;
        let sender = sender;
        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(err) => {
                    warn!(error = %err, "ringbuf readiness error");
                    continue;
                }
            };
            while let Some(item) = guard.get_inner_mut().next() {
                if let Some(event) = parse_event("ringbuf", item.as_ref()) {
                    if let Some(req) = event_to_ingest_request("ringbuf", &event) {
                        if sender.send(req).await.is_err() {
                            warn!("traffic channel closed");
                            return;
                        }
                    }
                }
            }
            guard.clear_ready();
        }
    });
    Ok(())
}

fn spawn_perf_event_consumers(
    ebpf: &mut aya::Ebpf,
    sender: mpsc::Sender<IngestTrafficRequest>,
) -> Result<()> {
    let map = ebpf
        .take_map(PERF_EVENT_MAP_NAME)
        .ok_or_else(|| anyhow!(format!("perf array {} not found", PERF_EVENT_MAP_NAME)))?;
    let mut perf_array = PerfEventArray::try_from(map)
        .map_err(|err| anyhow!(format!("failed to create perf array: {err:?}")))?;
    let cpu_ids =
        online_cpus().map_err(|err| anyhow!(format!("failed to read online cpus: {err:?}")))?;
    for cpu_id in cpu_ids {
        let mut buf = perf_array.open(cpu_id, None).map_err(|err| {
            anyhow!(format!(
                "failed to open perf buffer on cpu {cpu_id}: {err:?}"
            ))
        })?;
        let sender = sender.clone();
        tokio::task::spawn_blocking(move || {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(size_of::<Event>()))
                .collect::<Vec<_>>();
            loop {
                match buf.read_events(&mut buffers) {
                    Ok(events) => {
                        if events.lost > 0 {
                            warn!(cpu = cpu_id, lost = events.lost, "perf events lost");
                        }
                        for i in 0..events.read {
                            let data = &buffers[i];
                            if let Some(event) = parse_event("perf", data) {
                                if let Some(req) = event_to_ingest_request("perf", &event) {
                                    if sender.blocking_send(req).is_err() {
                                        warn!("traffic channel closed");
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warn!(cpu = cpu_id, error = %err, "failed to read perf events");
                    }
                }
            }
        });
    }
    Ok(())
}

fn spawn_event_consumers(
    ebpf: &mut aya::Ebpf,
    supports_ringbuf: bool,
    supports_perf: bool,
    sender: mpsc::Sender<IngestTrafficRequest>,
) -> Result<()> {
    if supports_ringbuf {
        spawn_ringbuf_consumer(ebpf, sender)?;
    } else if supports_perf {
        spawn_perf_event_consumers(ebpf, sender)?;
    }
    Ok(())
}

impl PodRuntime {
    pub async fn new(opts: PodOptions) -> Result<Self> {
        let PodOptions { config } = opts;
        if config.workers == 0 {
            return Err(anyhow!("workers must be at least 1"));
        }
        Ok(Self { config })
    }

    pub async fn run(&self) -> Result<()> {
        let config = &self.config;
        info!(
            "Connecting to traffic-counter server at {}",
            config.server_addr
        );

        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env()) // Reads RUST_LOG
            .init();

        let client = TrafficIngestorClient::connect(config.server_addr.clone())
            .await
            .context("failed to connect to traffic-counter server")?;
        info!("Connected to traffic-counter server");
        let (stable_tx, stable_rx) = mpsc::channel(1024);
        let manager_client = client.clone();
        tokio::task::spawn(async move {
            run_grpc_manager(manager_client, stable_rx).await;
        });
        if !probe_memcg_based_accounting_support() {
            info!(
                "kernel version is older than 5.11, try to bump memlock rlimit for compatibility"
            );
            // Bump the memlock rlimit. This is needed for older kernels that don't use the
            // new memcg based accounting, see https://lwn.net/Articles/837122/
            // TODO: check kernel version and only do this for older kernels.
            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
            if ret != 0 {
                return Err(anyhow!(
                    "remove limit on locked memory failed, the error code for `setrlimit` is: {ret}"
                ));
            }
        }
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can reach for `Bpf::load_file` instead.
        let bytecode = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pod-provider-ebpf"));
        let bytecode_legacy =
            aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pod-provider-ebpf-legacy"));
        let supports_ringbuf = probe_ringbuf_support()?;
        let supports_perf = if supports_ringbuf {
            false
        } else {
            probe_perf_event_array_support()?
        };
        let mut ebpf = if supports_ringbuf {
            info!("ring buffer is supported, loading eBPF program with ring buffer support");
            aya::Ebpf::load(bytecode)?
        } else if supports_perf {
            warn!(
                "ring buffer is not supported but perf event array is supported, falling back to perf event array"
            );
            aya::Ebpf::load(bytecode_legacy)?
        } else {
            return Err(anyhow!(
                "ring buffer and perf event array are not supported, eBPF program won't be able to submit events"
            ));
        };
        // Initialize the eBPF logger. This will print any log messages from your eBPF program to the console.
        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        let (ingress_prog_name, egress_prog_name) = if supports_ringbuf {
            ("count_traffic_to_container", "count_traffic_from_container")
        } else {
            (
                "count_traffic_to_container_legacy",
                "count_traffic_from_container_legacy",
            )
        };

        let manager = EbpfManager::new()?;
        load_tc_programs(&manager, &mut ebpf, ingress_prog_name, egress_prog_name)?;
        spawn_event_consumers(&mut ebpf, supports_ringbuf, supports_perf, stable_tx)?;

        let netns_entries = discover_pod_netns()?;
        info!(
            "Discovered {} pod network namespaces on the host",
            netns_entries.len()
        );
        let mut attached = 0usize;

        for entry in netns_entries {
            let _guard = match NetnsGuard::enter(&entry.path) {
                Ok(guard) => guard,
                Err(err) => {
                    warn!(
                        pid = entry.pid,
                        inode = entry.inode,
                        "Failed to enter netns {}: {err}",
                        entry.path.display()
                    );
                    continue;
                }
            };

            if !current_netns_has_eth0() {
                debug!(
                    pid = entry.pid,
                    inode = entry.inode,
                    "Skipping netns {}: eth0 not found",
                    entry.path.display()
                );
                continue;
            }

            let attach_result = attach_tc_programs(
                &manager,
                &mut ebpf,
                ingress_prog_name,
                egress_prog_name,
                "eth0", //TODO: support configurable iface name in the future, but for now we can just hardcode it to eth0
                        // since that's the default iface name for kubenet and most CNI plugins
            );
            if let Err(err) = attach_result {
                warn!(
                    pid = entry.pid,
                    inode = entry.inode,
                    "Failed to attach tc programs on eth0 in netns {}: {err}",
                    entry.path.display()
                );
                continue;
            }

            attached += 1;
        }

        info!(
            "Attached eBPF programs in {} pod network namespaces",
            attached
        );

        tokio::signal::ctrl_c()
            .await
            .context("failed to wait for ctrl-c")?;
        info!("received shutdown signal, exiting...");
        Ok(())
    }
}
