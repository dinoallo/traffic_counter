use std::process::exit;
use std::time::Duration;

use anyhow::Result;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};

mod node;

#[derive(Parser)]
#[command(name = "traffic-counter")]
#[command(about = "Traffic counter userspace agent", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run packet-socket ingestion pipeline
    Node(NodeCommand),
}

#[derive(Args)]
struct NodeCommand {
    /// Network interface to join via AF_PACKET
    #[arg(long, value_name = "IFACE")]
    iface: String,
    /// Number of worker threads pulling frames from the fanout group
    #[arg(long, default_value_t = 1)]
    workers: usize,
    /// Optional PACKET_FANOUT group id
    #[arg(long, value_name = "GROUP")]
    fanout_group: Option<u16>,
    /// Seconds between stat snapshots printed to stdout
    #[arg(long, default_value_t = 5)]
    report_interval_secs: u64,
    /// Size of each tpacket block (bytes)
    #[arg(long, value_name = "BYTES", default_value_t = node::DEFAULT_BLOCK_SIZE)]
    block_size: u32,
    /// Number of blocks provisioned for the RX ring
    #[arg(long, value_name = "COUNT", default_value_t = node::DEFAULT_BLOCK_COUNT)]
    block_count: u32,
    /// Size of each frame within a block (bytes)
    #[arg(long, value_name = "BYTES", default_value_t = node::DEFAULT_FRAME_SIZE)]
    frame_size: u32,
    /// Milliseconds before an idle block is recycled
    #[arg(long, value_name = "MILLIS", default_value_t = node::DEFAULT_BLOCK_TIMEOUT_MS)]
    block_timeout_ms: u32,
    /// Disable the socket-level classic BPF filter
    #[arg(long = "no-bpf-filter", action = ArgAction::SetTrue)]
    disable_bpf_filter: bool,
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
        Some(Commands::Node(cmd)) => {
            let opts = node::NodeOptions {
                iface: cmd.iface,
                workers: cmd.workers,
                fanout_group: cmd.fanout_group,
                report_interval: Duration::from_secs(cmd.report_interval_secs.max(1)),
                ring: node::RingConfig {
                    block_size: cmd.block_size,
                    block_count: cmd.block_count,
                    frame_size: cmd.frame_size,
                    block_timeout_ms: cmd.block_timeout_ms,
                },
            };
            node::run_packet_pipeline(opts).await?;
        }
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }

    Ok(())
}
