use anyhow::{Context, Result, anyhow};
use aya::programs::SchedClassifier;
use pod_provider_common::Direction;
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
                "eth0",
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
