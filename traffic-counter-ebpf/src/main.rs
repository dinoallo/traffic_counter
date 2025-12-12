#![no_std]
#![no_main]

use aya_ebpf::bindings::{TC_ACT_OK, xdp_action};
use aya_ebpf::macros::{classifier, map, xdp};
use aya_ebpf::maps::{Array, LruHashMap, PerCpuHashMap};
use aya_ebpf::programs::{TcContext, XdpContext};
use traffic_counter_common::{ControlConfig, Counters, FlowKey, IpKey};

const ETH_HDR_SIZE: usize = 14;
const IPV4_MIN_HEADER_BYTES: usize = 20;
const IPV6_HEADER_BYTES: usize = 40;
const CONTROL_SLOT_RUNTIME: u32 = 0;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

#[map(name = "traffic_counters_ip")]
static TRAFFIC_COUNTERS_IP: PerCpuHashMap<IpKey, Counters> =
    PerCpuHashMap::<IpKey, Counters>::with_max_entries(65536, 0);

#[map(name = "traffic_counters_flow")]
static TRAFFIC_COUNTERS_FLOW: LruHashMap<FlowKey, Counters> =
    LruHashMap::<FlowKey, Counters>::with_max_entries(32768, 0);

#[map(name = "traffic_control")]
static TRAFFIC_CONTROL: Array<ControlConfig> = Array::<ControlConfig>::with_max_entries(1, 0);

#[xdp]
pub fn xdp_traffic_counter(ctx: XdpContext) -> u32 {
    if process_packet(ctx.data() as *const u8, ctx.data_end() as *const u8).is_err() {
        record_drop();
    }
    xdp_action::XDP_PASS
}

#[classifier]
pub fn tc_traffic_counter(ctx: TcContext) -> i32 {
    if process_packet(ctx.data() as *const u8, ctx.data_end() as *const u8).is_err() {
        record_drop();
    }
    TC_ACT_OK
}

fn process_packet(data: *const u8, data_end: *const u8) -> Result<(), ()> {
    if unsafe { data.add(ETH_HDR_SIZE) } > data_end {
        return Err(());
    }

    const H_PROTO_OFFSET: usize = 12;
    if unsafe { data.add(H_PROTO_OFFSET + 1) } > data_end {
        return Err(());
    }

    let h_proto = unsafe {
        let p = data.add(H_PROTO_OFFSET) as *const u16;
        u16::from_be(core::ptr::read_unaligned(p))
    };

    let pkt_len = (data_end as usize).saturating_sub(data as usize) as u64;

    match h_proto {
        0x0800 => process_ipv4(data, data_end, pkt_len),
        0x86DD => process_ipv6(data, data_end, pkt_len),
        _ => Ok(()),
    }
}

fn process_ipv4(data: *const u8, data_end: *const u8, pkt_len: u64) -> Result<(), ()> {
    if unsafe { data.add(ETH_HDR_SIZE + IPV4_MIN_HEADER_BYTES) } > data_end {
        return Err(());
    }

    let ip_start = unsafe { data.add(ETH_HDR_SIZE) };
    let version_ihl = unsafe { *ip_start };
    if version_ihl >> 4 != 4 {
        return Err(());
    }
    let ihl_words = (version_ihl & 0x0f) as usize;
    if ihl_words < 5 {
        return Err(());
    }
    let header_len = ihl_words * 4;
    if unsafe { data.add(ETH_HDR_SIZE + header_len) } > data_end {
        return Err(());
    }

    let proto = unsafe { *ip_start.add(9) };

    let src = unsafe {
        let ptr = ip_start.add(12) as *const u32;
        u32::from_be(core::ptr::read_unaligned(ptr)) as u64
    };
    let dst = unsafe {
        let ptr = ip_start.add(16) as *const u32;
        u32::from_be(core::ptr::read_unaligned(ptr)) as u64
    };

    let key = IpKey {
        family: 2,
        pad: [0u8; 7],
        addr_lo: src,
        addr_hi: 0,
    };
    update_counters(&key, pkt_len);

    if should_track_flow(proto) {
        let l4_offset = ETH_HDR_SIZE + header_len;
        if let Some((src_port, dst_port)) = parse_ports(data, data_end, l4_offset) {
            update_flow_counters(2, proto, src, 0, dst, 0, src_port, dst_port, pkt_len);
        }
    }

    Ok(())
}

fn process_ipv6(data: *const u8, data_end: *const u8, pkt_len: u64) -> Result<(), ()> {
    if unsafe { data.add(ETH_HDR_SIZE + IPV6_HEADER_BYTES) } > data_end {
        return Err(());
    }

    let ip_start = unsafe { data.add(ETH_HDR_SIZE) };
    let proto = unsafe { *ip_start.add(6) };

    let src_hi = unsafe {
        let ptr = ip_start.add(8) as *const u64;
        u64::from_be(core::ptr::read_unaligned(ptr))
    };
    let src_lo = unsafe {
        let ptr = ip_start.add(16) as *const u64;
        u64::from_be(core::ptr::read_unaligned(ptr))
    };
    let dst_hi = unsafe {
        let ptr = ip_start.add(24) as *const u64;
        u64::from_be(core::ptr::read_unaligned(ptr))
    };
    let dst_lo = unsafe {
        let ptr = ip_start.add(32) as *const u64;
        u64::from_be(core::ptr::read_unaligned(ptr))
    };

    let key = IpKey {
        family: 10,
        pad: [0u8; 7],
        addr_lo: src_lo,
        addr_hi: src_hi,
    };
    update_counters(&key, pkt_len);

    if should_track_flow(proto) {
        let l4_offset = ETH_HDR_SIZE + IPV6_HEADER_BYTES;
        if let Some((src_port, dst_port)) = parse_ports(data, data_end, l4_offset) {
            update_flow_counters(
                10, proto, src_lo, src_hi, dst_lo, dst_hi, src_port, dst_port, pkt_len,
            );
        }
    }

    Ok(())
}

fn update_counters(key: &IpKey, pkt_len: u64) {
    match TRAFFIC_COUNTERS_IP.get_ptr_mut(key) {
        Some(ptr) => {
            let counters = unsafe { &mut *ptr };
            counters.bytes = counters.bytes.wrapping_add(pkt_len);
            counters.packets = counters.packets.wrapping_add(1);
        }
        None => {
            let init = Counters {
                bytes: pkt_len,
                packets: 1,
            };
            let _ = TRAFFIC_COUNTERS_IP.insert(key, &init, 0);
        }
    }
}

fn parse_ports(data: *const u8, data_end: *const u8, offset: usize) -> Option<(u16, u16)> {
    if unsafe { data.add(offset + 4) } > data_end {
        return None;
    }

    unsafe {
        let src_ptr = data.add(offset) as *const u16;
        let dst_ptr = data.add(offset + 2) as *const u16;
        let src = u16::from_be(core::ptr::read_unaligned(src_ptr));
        let dst = u16::from_be(core::ptr::read_unaligned(dst_ptr));
        Some((src, dst))
    }
}

fn should_track_flow(proto: u8) -> bool {
    proto == PROTO_TCP || proto == PROTO_UDP
}

fn update_flow_counters(
    family: u8,
    proto: u8,
    src_addr_lo: u64,
    src_addr_hi: u64,
    dst_addr_lo: u64,
    dst_addr_hi: u64,
    src_port: u16,
    dst_port: u16,
    pkt_len: u64,
) {
    if !flow_tracking_enabled() {
        return;
    }

    let key = FlowKey {
        family,
        proto,
        pad0: [0u8; 2],
        src_port,
        dst_port,
        pad1: 0,
        src_addr_lo,
        src_addr_hi,
        dst_addr_lo,
        dst_addr_hi,
    };

    match TRAFFIC_COUNTERS_FLOW.get_ptr_mut(&key) {
        Some(ptr) => {
            let counters = unsafe { &mut *ptr };
            counters.bytes = counters.bytes.wrapping_add(pkt_len);
            counters.packets = counters.packets.wrapping_add(1);
        }
        None => {
            let init = Counters {
                bytes: pkt_len,
                packets: 1,
            };
            let _ = TRAFFIC_COUNTERS_FLOW.insert(&key, &init, 0);
        }
    }
}

fn flow_tracking_enabled() -> bool {
    match TRAFFIC_CONTROL.get_ptr(CONTROL_SLOT_RUNTIME) {
        Some(ptr) => unsafe { (*ptr).enable_flow_counters != 0 },
        None => false,
    }
}

fn record_drop() {
    if let Some(ptr) = TRAFFIC_CONTROL.get_ptr_mut(CONTROL_SLOT_RUNTIME) {
        unsafe {
            (*ptr).dropped_packets = (*ptr).dropped_packets.wrapping_add(1);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
