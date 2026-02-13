use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::node::NodeOptions;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
mod defaults;
mod model;
mod node;
mod packet;
#[derive(Parser)]
#[command(name = "node-provider")]
#[command(about = "Traffic counter node provider", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    // Version(VersionCommand),
    Run(RunCommand),
}

#[derive(Args)]
#[command(author, about = "Count traffic of a network interface on a node", long_about = None)]
struct RunCommand {
    /// Address of the traffic-counter gRPC server
    #[arg(
        long,
        value_name = "SERVER_ADDR",
        default_value = defaults::DEFAULT_SERVER_ADDR
    )]
    server_addr: String,

    /// Network interface to join via AF_PACKET
    #[arg(long, value_name = "IFACE", default_value = defaults::DEFAULT_IFACE)]
    iface: String,
    /// Number of worker threads pulling frames from the fanout group
    #[arg(long, value_name = "NUMBER", default_value_t = defaults::DEFAULT_WORKERS)]
    workers: usize,
    /// Optional PACKET_FANOUT group id
    #[arg(long, value_name = "GROUP", default_value = None)]
    fanout_group: Option<u16>,
    /// Seconds between stat snapshots printed to stdout
    #[arg(long, value_name = "SECOND", default_value_t = defaults::DEFAULT_EXPORT_INTERVAL_SECS)]
    report_interval_secs: u64,
    /// Align report emissions to natural time boundaries (minute, hour, etc.)
    #[arg(long, value_name = "BOOLEAN", default_value_t = defaults::DEFAULT_EXPORT_NATURAL)]
    report_natural: bool,
    /// Size of each tpacket block (bytes)
    #[arg(long, value_name = "BYTES", default_value_t = defaults::DEFAULT_BLOCK_SIZE)]
    block_size: u32,
    /// Number of blocks provisioned for the RX ring
    #[arg(long, value_name = "COUNT", default_value_t = defaults::DEFAULT_BLOCK_COUNT)]
    block_count: u32,
    /// Size of each frame within a block (bytes)
    #[arg(long, value_name = "BYTES", default_value_t = defaults::DEFAULT_FRAME_SIZE)]
    frame_size: u32,
    /// Milliseconds before an idle block is recycled
    #[arg(long, value_name = "MILLIS", default_value_t = defaults::DEFAULT_BLOCK_TIMEOUT_MS)]
    block_timeout_ms: u32,
    /// File containing IPv4/IPv6 destination CIDRs to ignore (one per line)
    #[arg(long, value_name = "PATH", default_value = None)]
    remote_whitelist: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env()) // Reads RUST_LOG
        .init();
    if let Err(err) = run().await {
        eprintln!("node provider error: {err:?}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // Some(Commands::Version(_)) => {
        //     println!("node provider version {VERSION} ({GIT_DESCRIBE})");
        // }
        Some(Commands::Run(cmd)) => {
            let config = node::NodeConfig {
                server_addr: cmd.server_addr,
                iface: cmd.iface,
                workers: cmd.workers,
                fanout_group: cmd.fanout_group,
                ring: node::RingConfig {
                    block_size: cmd.block_size,
                    block_count: cmd.block_count,
                    frame_size: cmd.frame_size,
                    block_timeout_ms: cmd.block_timeout_ms,
                },
                remote_whitelist: cmd.remote_whitelist,
            };
            let runtime = node::NodeRuntime::new(NodeOptions { config }).await?;
            runtime.run().await?;
        }
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }

    Ok(())
}
