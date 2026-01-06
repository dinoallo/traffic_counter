fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "wasm32" {
        tonic_build::configure()
            .build_server(false)
            .build_client(false)
            .compile(&["proto/traffic.proto"], &["proto"])?;
    } else {
        tonic_build::configure()
            .build_server(true)
            .build_client(true)
            .compile(&["proto/traffic.proto"], &["proto"])?;
    }
    Ok(())
}
