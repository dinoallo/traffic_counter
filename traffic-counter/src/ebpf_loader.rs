use std::{
    convert::TryFrom,
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, ensure};
use aya::pin::PinError;
use aya::programs::tc::{SchedClassifier, SchedClassifierLinkId, TcAttachType};
use aya::programs::xdp::XdpLinkId;
use aya::programs::{Xdp, XdpFlags};
use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    maps::{Array, Map, MapData, PerCpuHashMap, PerCpuValues},
};
use clap::ValueEnum;
use serde_json::{Map as JsonMap, Number as JsonNumber, Value};
use tokio::signal;

use traffic_counter_common::{ControlConfig, Counters, IpKey};

const EBPF_BYTES: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/traffic-counter"));
const MAP_TRAFFIC_COUNTERS: &str = "traffic_counters_ip";
const MAP_TRAFFIC_FLOWS: &str = "traffic_counters_flow";
const MAP_TRAFFIC_CONTROL: &str = "traffic_control";
const XDP_PROGRAM: &str = "xdp_traffic_counter";
const TC_PROGRAM: &str = "tc_traffic_counter";
const CONTROL_SLOT_RUNTIME: u32 = 0;

pub const DEFAULT_IP_MAP_PIN: &str = "/sys/fs/bpf/traffic_counter/traffic_counters_ip";
pub const DEFAULT_FLOW_MAP_PIN: &str = "/sys/fs/bpf/traffic_counter/traffic_counters_flow";
pub const DEFAULT_CONTROL_MAP_PIN: &str = "/sys/fs/bpf/traffic_counter/traffic_control";

/// Aggregate per-CPU counters from a pinned per-CPU hash map via aya.
///
/// `pin_path` should be the path to the pinned map (defaults to `DEFAULT_IP_MAP_PIN`).
/// Returns a JSON array where each element is an object with `key`, `bytes`, and `packets`.
pub fn aggregate_per_cpu_counters<P: AsRef<Path>>(pin_path: P) -> Result<Value> {
    let pin = pin_path.as_ref();

    let map_data =
        MapData::from_pin(pin).map_err(|e| anyhow!("failed to open pinned map: {}", e))?;
    let map_enum = Map::from_map_data(map_data).map_err(|e| anyhow!("invalid map type: {}", e))?;
    let per_cpu_map = PerCpuHashMap::<_, IpKey, Counters>::try_from(map_enum)
        .map_err(|e| anyhow!("failed to convert to PerCpuHashMap: {}", e))?;

    let mut aggregated = Vec::new();

    for item in per_cpu_map.iter() {
        let (key, per_cpu_vals): (IpKey, PerCpuValues<Counters>) =
            item.map_err(|e| anyhow!("aya iter error: {}", e))?;

        let (bytes_total, packets_total) = sum_counters(per_cpu_vals.iter());

        let mut obj = JsonMap::new();
        obj.insert("key".to_string(), Value::String(format!("{:?}", key)));
        obj.insert("bytes".to_string(), value_from_u128(bytes_total));
        obj.insert("packets".to_string(), value_from_u128(packets_total));
        aggregated.push(Value::Object(obj));
    }

    Ok(Value::Array(aggregated))
}

fn sum_counters<'a, I>(values: I) -> (u128, u128)
where
    I: IntoIterator<Item = &'a Counters>,
{
    let mut bytes_total: u128 = 0;
    let mut packets_total: u128 = 0;
    for v in values {
        bytes_total = bytes_total.wrapping_add(v.bytes as u128);
        packets_total = packets_total.wrapping_add(v.packets as u128);
    }
    (bytes_total, packets_total)
}

fn value_from_u128(n: u128) -> Value {
    if n <= u64::MAX as u128 {
        Value::Number(JsonNumber::from(n as u64))
    } else {
        Value::String(n.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Number as JsonNumber;

    #[test]
    fn sum_counters_accumulates_multiple_cpus() {
        let cpus = vec![
            Counters {
                bytes: 100,
                packets: 2,
            },
            Counters {
                bytes: 50,
                packets: 1,
            },
        ];
        let (bytes, packets) = sum_counters(cpus.iter());
        assert_eq!(bytes, 150);
        assert_eq!(packets, 3);
    }

    #[test]
    fn sum_counters_handles_large_values() {
        let cpus = vec![
            Counters {
                bytes: u64::MAX,
                packets: u64::MAX,
            },
            Counters {
                bytes: 1,
                packets: 1,
            },
        ];
        let (bytes, packets) = sum_counters(cpus.iter());
        assert_eq!(bytes, (u64::MAX as u128) + 1);
        assert_eq!(packets, (u64::MAX as u128) + 1);
    }

    #[test]
    fn value_from_u128_formats_numbers() {
        match value_from_u128(42) {
            Value::Number(n) => assert_eq!(n, JsonNumber::from(42)),
            other => panic!("unexpected value: {other:?}"),
        }

        let big = (u64::MAX as u128) + 5;
        match value_from_u128(big) {
            Value::String(s) => assert_eq!(s, big.to_string()),
            other => panic!("expected string, got {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AttachPoint {
    Xdp,
    TcIngress,
    TcEgress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum XdpMode {
    Skb,
    Driver,
    Hw,
}

#[derive(Clone, Debug)]
pub struct AttachOptions {
    pub iface: String,
    pub pin_path: PathBuf,
    pub flow_pin_path: PathBuf,
    pub control_pin_path: PathBuf,
    pub attach_point: AttachPoint,
    pub xdp_mode: XdpMode,
    pub ip_map_entries: u32,
    pub flow_map_entries: u32,
    pub enable_flow_counters: bool,
}

pub async fn attach_program(opts: AttachOptions) -> Result<()> {
    validate_attach_options(&opts)?;

    let mut loader = EbpfLoader::new();
    #[allow(deprecated)]
    {
        // `set_max_entries` is currently the only stable API across our Aya pin.
        loader.set_max_entries(MAP_TRAFFIC_COUNTERS, opts.ip_map_entries);
        loader.set_max_entries(MAP_TRAFFIC_FLOWS, opts.flow_map_entries);
    }

    let mut bpf = loader
        .load(EBPF_BYTES)
        .context("failed to load eBPF object")?;

    let control_block = ControlConfig {
        enable_flow_counters: opts.enable_flow_counters as u8,
        reserved: [0; 7],
        ip_map_capacity: opts.ip_map_entries,
        flow_map_capacity: opts.flow_map_entries,
        dropped_packets: 0,
    };
    write_control_config(&mut bpf, control_block)?;

    pin_map(&mut bpf, MAP_TRAFFIC_COUNTERS, &opts.pin_path)?;
    pin_map(&mut bpf, MAP_TRAFFIC_FLOWS, &opts.flow_pin_path)?;
    pin_map(&mut bpf, MAP_TRAFFIC_CONTROL, &opts.control_pin_path)?;

    let handle = match opts.attach_point {
        AttachPoint::Xdp => LinkHandle::Xdp(attach_xdp(&mut bpf, &opts.iface, opts.xdp_mode)?),
        AttachPoint::TcIngress => {
            LinkHandle::Tc(attach_tc(&mut bpf, &opts.iface, TcAttachType::Ingress)?)
        }
        AttachPoint::TcEgress => {
            LinkHandle::Tc(attach_tc(&mut bpf, &opts.iface, TcAttachType::Egress)?)
        }
    };

    println!(
        "Attached {:?} program to {}. Press Ctrl+C to detach.",
        opts.attach_point, opts.iface
    );

    signal::ctrl_c()
        .await
        .context("failed to wait for shutdown signal")?;

    println!("Detaching {:?} from {}...", opts.attach_point, opts.iface);
    detach(&mut bpf, handle)?;
    Ok(())
}

fn validate_attach_options(opts: &AttachOptions) -> Result<()> {
    ensure!(
        opts.ip_map_entries > 0,
        "ip map size must be greater than zero"
    );
    ensure!(
        opts.flow_map_entries > 0,
        "flow map size must be greater than zero"
    );
    Ok(())
}

fn write_control_config(bpf: &mut Ebpf, cfg: ControlConfig) -> Result<()> {
    let map = bpf
        .map_mut(MAP_TRAFFIC_CONTROL)
        .with_context(|| format!("map {MAP_TRAFFIC_CONTROL} not found"))?;
    let mut array =
        Array::<_, ControlConfig>::try_from(map).context("control map has unexpected type")?;
    array
        .set(CONTROL_SLOT_RUNTIME, cfg, 0)
        .with_context(|| "failed to write control block")?;
    Ok(())
}

fn pin_map(bpf: &mut Ebpf, map_name: &str, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let map = bpf
        .map_mut(map_name)
        .with_context(|| format!("map {map_name} not found"))?;
    match map.pin(path) {
        Ok(()) => Ok(()),
        Err(PinError::SyscallError(err)) if err.io_error.kind() == io::ErrorKind::AlreadyExists => {
            Ok(())
        }
        Err(err) => Err(anyhow!(
            "failed to pin map {map_name} at {}: {err}",
            path.display()
        )),
    }
}

enum LinkHandle {
    Xdp(XdpLinkId),
    Tc(SchedClassifierLinkId),
}

fn attach_xdp(bpf: &mut Ebpf, iface: &str, mode: XdpMode) -> Result<XdpLinkId> {
    let flags = xdp_flags(mode);
    let program: &mut Xdp = bpf
        .program_mut(XDP_PROGRAM)
        .with_context(|| format!("program {XDP_PROGRAM} not found"))?
        .try_into()
        .context("xdp program has wrong type")?;
    program.load().context("failed to load xdp program")?;
    program
        .attach(iface, flags)
        .with_context(|| format!("failed to attach xdp on {iface}"))
}

fn attach_tc(
    bpf: &mut Ebpf,
    iface: &str,
    attach_type: TcAttachType,
) -> Result<SchedClassifierLinkId> {
    let program: &mut SchedClassifier = bpf
        .program_mut(TC_PROGRAM)
        .with_context(|| format!("program {TC_PROGRAM} not found"))?
        .try_into()
        .context("tc program has wrong type")?;
    program.load().context("failed to load tc program")?;
    program
        .attach(iface, attach_type)
        .with_context(|| format!("failed to attach tc on {iface}"))
}

fn detach(bpf: &mut Ebpf, handle: LinkHandle) -> Result<()> {
    match handle {
        LinkHandle::Xdp(id) => {
            let program: &mut Xdp = bpf
                .program_mut(XDP_PROGRAM)
                .with_context(|| format!("program {XDP_PROGRAM} not found"))?
                .try_into()
                .context("xdp program has wrong type")?;
            program.detach(id).context("failed to detach xdp program")
        }
        LinkHandle::Tc(id) => {
            let program: &mut SchedClassifier = bpf
                .program_mut(TC_PROGRAM)
                .with_context(|| format!("program {TC_PROGRAM} not found"))?
                .try_into()
                .context("tc program has wrong type")?;
            program.detach(id).context("failed to detach tc program")
        }
    }
}

fn xdp_flags(mode: XdpMode) -> XdpFlags {
    match mode {
        XdpMode::Skb => XdpFlags::SKB_MODE,
        XdpMode::Driver => XdpFlags::DRV_MODE,
        XdpMode::Hw => XdpFlags::HW_MODE,
    }
}
