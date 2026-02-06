use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::export::Export;
use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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
    Run(RunArgs),
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ExportMode {
    Log,
    Prometheus,
}

#[derive(Args)]
struct VersionCommand;

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    serve_config: serve::ServeConfig,

    //TODO: merge the following export-related args into a separate ExportConfig struct
    /// Export interval in seconds
    #[arg(long, default_value = "5")]
    export_interval_secs: u64,

    /// Exporter backend to use
    #[arg(long, value_enum, default_value = "log")]
    export_mode: ExportMode,

    /// Address for the Prometheus exporter to listen on
    #[arg(long, default_value = "0.0.0.0:9090")]
    prometheus_listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env()) // Reads RUST_LOG
        .init();
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
        Some(Commands::Run(args)) => {
            let k8s_inquirer = Arc::new(k8s::K8sInquirer::new().await?);
            let k8s_labeler = label::K8sTrafficLabeler::new(k8s_inquirer);
            let labeler = Arc::new(label::TrafficLabeler::new(k8s_labeler));
            let aggregator = Arc::new(store::TrafficCounter::default());

            let factory = Arc::new(factory::TrafficFactory::new(labeler, aggregator.clone()));

            let traffic_dumper: Arc<dyn store::TrafficDump> = aggregator.clone();

            let running = Arc::new(AtomicBool::new(true));
            let interval = Duration::from_secs(args.export_interval_secs);

            match args.export_mode {
                ExportMode::Log => {
                    let exporter = export::LogExporter::new(traffic_dumper.clone());
                    let running_clone = running.clone();
                    tokio::spawn(async move {
                        if let Err(e) = exporter.run(running_clone, interval, false).await {
                            eprintln!("Exporter failed: {e:?}");
                        }
                    });
                }
                ExportMode::Prometheus => {
                    let exporter = export::PrometheusExporter::new(
                        traffic_dumper.clone(),
                        args.prometheus_listen_addr,
                    )?;
                    let running_clone = running.clone();
                    tokio::spawn(async move {
                        if let Err(e) = exporter.run(running_clone, interval, false).await {
                            eprintln!("Exporter failed: {e:?}");
                        }
                    });
                }
            }

            let server = serve::Server::new(args.serve_config, factory);
            server.run().await?;
        }
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }

    Ok(())
}
