use std::process::exit;

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand};

mod export;
mod factory;
mod k8s;
mod label;
mod serve;
mod store;

const VERSION: &str = env!("TRAFFIC_COUNTER_VERSION");
const GIT_DESCRIBE: &str = match option_env!("TRAFFIC_COUNTER_GIT_DESC") {
    Some(desc) => desc,
    None => "unknown",
};

#[derive(Parser)]
#[command(name = "traffic-counter")]
#[command(about = "Traffic counter userspace agent", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Version(VersionCommand),
}

#[derive(Args)]
struct VersionCommand;

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
        Some(Commands::Version(_)) => {
            println!("traffic-counter {VERSION} ({GIT_DESCRIBE})");
        }
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }

    Ok(())
}
