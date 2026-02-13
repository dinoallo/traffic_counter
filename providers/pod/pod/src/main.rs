use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand};

mod defaults;
mod ebpf;
mod netns;
mod pod;
mod probe;

use pod::{PodConfig, PodOptions, PodRuntime};
#[derive(Parser)]
#[command(name = "pod-provider")]
#[command(about = "Traffic counter provider for Kubernetes pods", long_about = None)]
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
#[command(author, about = "Run the pod provider", long_about = None)]
struct RunCommand {
    #[arg(
        long,
        value_name = "SERVER_ADDR",
        default_value = defaults::DEFAULT_SERVER_ADDR
    )]
    server_addr: String,
    /// Number of worker threads
    #[arg(long, value_name = "NUMBER", default_value_t = defaults::DEFAULT_WORKERS)]
    workers: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Run(cmd)) => {
            let runtime = PodRuntime::new(PodOptions {
                config: PodConfig {
                    server_addr: cmd.server_addr,
                    workers: cmd.workers,
                },
            })
            .await?;
            runtime.run().await?;
        }
        None => {
            Cli::command().print_help()?;
        }
    }
    Ok(())
}
