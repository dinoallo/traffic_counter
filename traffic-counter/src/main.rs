use std::path::PathBuf;
use std::process::exit;

use anyhow::Result;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};

mod ebpf_loader;

#[derive(Parser)]
#[command(name = "traffic-counter")]
#[command(about = "Traffic counter userspace agent", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Load and attach the eBPF program
    Attach(AttachCommand),
    /// Dump and aggregate pinned eBPF maps (per-CPU counters)
    DumpMaps(DumpMapsCommand),
}

#[derive(Args)]
struct AttachCommand {
    /// Network interface to attach to
    #[arg(long, value_name = "IFACE")]
    iface: String,
    /// Attach point (xdp, tc-ingress, tc-egress)
    #[arg(long, value_enum, default_value_t = ebpf_loader::AttachPoint::Xdp)]
    attach_point: ebpf_loader::AttachPoint,
    /// XDP mode when --attach-point=xdp
    #[arg(long, value_enum, default_value_t = ebpf_loader::XdpMode::Skb)]
    xdp_mode: ebpf_loader::XdpMode,
    /// Path where the per-CPU counter map should be pinned
    #[arg(long, value_name = "PIN_PATH", default_value = ebpf_loader::DEFAULT_IP_MAP_PIN)]
    pin: PathBuf,
    /// Path where the flow counter map should be pinned
    #[arg(long, value_name = "PIN_PATH", default_value = ebpf_loader::DEFAULT_FLOW_MAP_PIN)]
    flow_pin: PathBuf,
    /// Path where the control map should be pinned
    #[arg(long, value_name = "PIN_PATH", default_value = ebpf_loader::DEFAULT_CONTROL_MAP_PIN)]
    control_pin: PathBuf,
    /// Number of entries provisioned for the per-IP per-CPU map
    #[arg(long, value_name = "COUNT", default_value_t = 65_536)]
    ip_map_size: u32,
    /// Number of entries provisioned for the LRU flow map
    #[arg(long, value_name = "COUNT", default_value_t = 32_768)]
    flow_map_size: u32,
    /// Enable flow tracking (updates the LRU map)
    #[arg(long, action = ArgAction::SetTrue)]
    enable_flow_map: bool,
}

#[derive(Args)]
struct DumpMapsCommand {
    /// Path to the pinned map (e.g. /sys/fs/bpf/traffic_counter/traffic_counters_ip)
    #[arg(long, value_name = "PIN_PATH", default_value = ebpf_loader::DEFAULT_IP_MAP_PIN)]
    pin: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("traffic-counter error: {err:?}");
        exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Attach(cmd)) => {
            let opts = ebpf_loader::AttachOptions {
                iface: cmd.iface,
                pin_path: cmd.pin,
                flow_pin_path: cmd.flow_pin,
                control_pin_path: cmd.control_pin,
                attach_point: cmd.attach_point,
                xdp_mode: cmd.xdp_mode,
                ip_map_entries: cmd.ip_map_size,
                flow_map_entries: cmd.flow_map_size,
                enable_flow_counters: cmd.enable_flow_map,
            };
            ebpf_loader::attach_program(opts).await?;
        }
        Some(Commands::DumpMaps(cmd)) => {
            let val = ebpf_loader::aggregate_per_cpu_counters(&cmd.pin)?;
            println!("{}", serde_json::to_string_pretty(&val)?);
        }
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }

    Ok(())
}
