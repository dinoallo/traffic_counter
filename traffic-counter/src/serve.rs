use clap::Args;
#[derive(Args)]
pub struct ServeConfig;

pub struct Server {
    config: ServeConfig,
}
