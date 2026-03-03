#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_UNSPEC,
    macros::{classifier, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::TcContext,
};
use aya_log_ebpf::{debug, error};
use pod_provider_common::{Direction, Event};

const EVENT_LEGACY_FLAGS: u32 = 0;
#[map]
static EVENTS_LEGACY: PerfEventArray<Event> = PerfEventArray::new(EVENT_LEGACY_FLAGS);
static HEAP: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);
#[classifier]
pub fn count_traffic_from_container_legacy(ctx: TcContext) -> i32 {
    match count_traffic_legacy(ctx, Direction::Egress) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
#[classifier]
pub fn count_traffic_to_container_legacy(ctx: TcContext) -> i32 {
    match count_traffic_legacy(ctx, Direction::Ingress) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
#[inline(always)]
fn count_traffic_legacy(ctx: TcContext, dir: Direction) -> Result<i32, i32> {
    // Check if the skb is null.
    if ctx.skb.skb.is_null() {
        return Err(0);
    }
    let mut event: Event = match HEAP.get_ptr_mut(0) {
        Some(e) => unsafe { *e },
        None => {
            error!(&ctx, "Failed to get pointer from per-cpu array");
            return Err(TC_ACT_UNSPEC);
        }
    };

    match dir {
        Direction::Ingress => {
            event = Event {
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
            }
        }
        Direction::Egress => {
            event = Event {
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
            }
        }
    }
    let submit_flags: u32 = 0;
    debug!(
        &ctx,
        "Submit event: len={}, protocol={}, family={}", event.len, event.protocol, event.family,
    );
    EVENTS_LEGACY.output(&ctx, &event, submit_flags);
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
