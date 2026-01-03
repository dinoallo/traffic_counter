use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::node::NodeOptions;
mod model;
mod node;
mod packet;
#[derive(Parser)]
#[command(name = "node")]
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
    /// Align report emissions to natural time boundaries (minute, hour, etc.)
    #[arg(long)]
    report_natural: bool,
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
    /// File containing IPv4/IPv6 destination CIDRs to ignore (one per line)
    #[arg(long, value_name = "PATH")]
    ignore_file: Option<PathBuf>,
    /// File containing IPv4/IPv6 source CIDRs to accept (one per line)
    #[arg(long, value_name = "PATH")]
    accept_source_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
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
                iface: cmd.iface,
                workers: cmd.workers,
                fanout_group: cmd.fanout_group,
                ring: node::RingConfig {
                    block_size: cmd.block_size,
                    block_count: cmd.block_count,
                    frame_size: cmd.frame_size,
                    block_timeout_ms: cmd.block_timeout_ms,
                },
                remote_whitelist: cmd.ignore_file,
                local_addresslist: cmd.accept_source_file,
            };
            let runtime = node::NodeRuntime::new(NodeOptions { config })?;
            runtime.run().await?;
        }
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }

    Ok(())
}
