#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
// use core::mem;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IpKey {
    pub family: u8,
    pub pad: [u8; 7],
    pub addr_lo: u64,
    pub addr_hi: u64,
}

#[repr(C)]
pub struct Counters {
    pub bytes: u64,
    pub packets: u64,
}

#[map(name = "traffic_counters_ip")]
static TRAFFIC_COUNTERS_IP: HashMap<IpKey, Counters> =
    HashMap::<IpKey, Counters>::with_max_entries(65536, 0);

#[xdp]
pub fn xdp_traffic_counter(ctx: XdpContext) -> u32 {
    match try_xdp_traffic_counter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_traffic_counter(ctx: XdpContext) -> Result<u32, i64> {
    // Safe wrappers to access packet data
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    // Basic bounds check for ethernet header
    let eth_hdr_size = core::mem::size_of::<u16>() * 6 + core::mem::size_of::<u16>();
    if unsafe { data.add(eth_hdr_size) } > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Read ethernet proto (offset 12)
    let h_proto_offset = 12usize;
    if unsafe { data.add(h_proto_offset + 1) } > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let h_proto = unsafe {
        let p = data.add(h_proto_offset) as *const u16;
        u16::from_be(core::ptr::read_unaligned(p))
    };

    // packet length
    let pkt_len = (data_end as usize).saturating_sub(data as usize) as u64;

    // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
    if h_proto == 0x0800u16 {
        // IPv4: parse source address at ethernet + 14 + 12
        let ip_saddr_offset = 14usize + 12usize;
        if unsafe { data.add(ip_saddr_offset + 3) } > data_end {
            return Ok(xdp_action::XDP_PASS);
        }

        let mut key = IpKey {
            family: 2u8,
            pad: [0u8; 7],
            addr_lo: 0,
            addr_hi: 0,
        };
        unsafe {
            let src_ptr = data.add(ip_saddr_offset) as *const u32;
            let saddr = core::ptr::read_unaligned(src_ptr) as u32;
            key.addr_lo = saddr as u64;
        }
        match TRAFFIC_COUNTERS_IP.get_ptr_mut(key) {
            Some(v) => {
                let counters = unsafe { &mut *v };
                counters.bytes = counters.bytes.wrapping_add(pkt_len);
                counters.packets = counters.packets.wrapping_add(1);
            }
            None => {
                let init = Counters {
                    bytes: pkt_len,
                    packets: 1,
                };
                let _ = TRAFFIC_COUNTERS_IP.insert(&key, &init, 0);
            }
        }
    } else if h_proto == 0x86DDu16 {
        // IPv6: parse source addr at ethernet + 14
        let ip6_saddr_offset = 14usize + 8usize; // source addr starts at byte 8 of IPv6 header
        if unsafe { data.add(ip6_saddr_offset + 15) } > data_end {
            return Ok(xdp_action::XDP_PASS);
        }

        let mut key = IpKey {
            family: 10u8,
            pad: [0u8; 7],
            addr_lo: 0,
            addr_hi: 0,
        };
        unsafe {
            // copy 16 bytes into addr_lo/addr_hi
            let src = data.add(14usize) as *const u8;
            // copy low 8
            let mut tmp_lo: u64 = 0;
            let mut tmp_hi: u64 = 0;
            let mut i = 0usize;
            while i < 8 {
                tmp_lo |= (core::ptr::read_unaligned(src.add(8 + i)) as u64) << (i * 8);
                i += 1;
            }
            i = 0;
            while i < 8 {
                tmp_hi |= (core::ptr::read_unaligned(src.add(i)) as u64) << (i * 8);
                i += 1;
            }
            key.addr_lo = tmp_lo;
            key.addr_hi = tmp_hi;
        }
        match TRAFFIC_COUNTERS_IP.get_ptr_mut(&key) {
            Some(v) => {
                let counters = unsafe { &mut *v };
                counters.bytes = counters.bytes.wrapping_add(pkt_len);
                counters.packets = counters.packets.wrapping_add(1);
            }
            None => {
                let init = Counters {
                    bytes: pkt_len,
                    packets: 1,
                };
                let _ = TRAFFIC_COUNTERS_IP.insert(&key, &init, 0);
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
