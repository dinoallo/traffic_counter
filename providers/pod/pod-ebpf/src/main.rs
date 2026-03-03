#![no_std]
#![no_main]

use aya_ebpf::maps::RingBuf;
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::{
    bindings::TC_ACT_UNSPEC,
    macros::{classifier, map},
    programs::TcContext,
};
use aya_log_ebpf::{debug, warn};
use pod_provider_common::{Direction, Event};

const EVENT_MAX_ENTRIES: u32 = 1024;
const EVENT_MAX_SIZE: u32 = core::mem::size_of::<Event>() as u32 * EVENT_MAX_ENTRIES;
const EVENT_FLAGS: u32 = 0;
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(EVENT_MAX_SIZE, EVENT_FLAGS);

#[classifier]
pub fn count_traffic_from_container(ctx: TcContext) -> i32 {
    match count_traffic(ctx, Direction::Egress) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
#[classifier]
pub fn count_traffic_to_container(ctx: TcContext) -> i32 {
    match count_traffic(ctx, Direction::Ingress) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn count_traffic(ctx: TcContext, dir: Direction) -> Result<i32, i32> {
    // Check if the skb is null.
    if ctx.skb.skb.is_null() {
        return Err(0);
    }
    let reserved_flags: u64 = 0;
    let mut entry: RingBufEntry<Event> = match EVENTS.reserve(reserved_flags) {
        Some(e) => e,
        None => {
            return {
                //TODO: add a counter for this case and log it.
                warn!(&ctx, "Failed to reserve space in ring buffer");
                Err(TC_ACT_UNSPEC)
            };
        }
    };
    // TODO: check me
    let e = entry.write(Event::default());
    match dir {
        Direction::Ingress => {
            *e = Event {
                len: ctx.len(),
                protocol: ctx.skb.protocol(),
                family: ctx.skb.family(),
                local_ipv4: ctx.skb.remote_ipv4(),
                local_ipv6: *ctx.skb.remote_ipv6(),
                remote_ipv4: ctx.skb.local_ipv4(),
                remote_ipv6: *ctx.skb.local_ipv6(),
                local_port: ctx.skb.remote_port(),
                remote_port: ctx.skb.local_port(),
                direction: dir as u32,
            };
        }
        Direction::Egress => {
            *e = Event {
                len: ctx.len(),
                protocol: ctx.skb.protocol(),
                family: ctx.skb.family(),
                local_ipv4: ctx.skb.local_ipv4(),
                local_ipv6: *ctx.skb.local_ipv6(),
                remote_ipv4: ctx.skb.remote_ipv4(),
                remote_ipv6: *ctx.skb.remote_ipv6(),
                local_port: ctx.skb.local_port(),
                remote_port: ctx.skb.remote_port(),
                direction: dir as u32,
            };
        }
    }
    let submit_flags: u64 = 0;
    //TODO: log ipv6 addresses
    debug!(
        &ctx,
        "Submit event: len={}, protocol={}, family={}", e.len, e.protocol, e.family,
    );
    entry.submit(submit_flags);
    Ok(TC_ACT_UNSPEC)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
