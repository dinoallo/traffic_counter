use std::{
    ffi::CString,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    ptr, slice,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering, fence},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use tokio::{signal, task, time};

use traffic_counter_common::IpKey;

use crate::{
    model::AddressList,
    store::{CounterTable, log_snapshot},
};

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

pub const DEFAULT_BLOCK_SIZE: u32 = 1 << 20; // 1 MiB
pub const DEFAULT_BLOCK_COUNT: u32 = 64;
pub const DEFAULT_FRAME_SIZE: u32 = 2048;
pub const DEFAULT_BLOCK_TIMEOUT_MS: u32 = 100;

#[derive(Clone, Copy, Debug)]
pub struct RingConfig {
    pub block_size: u32,
    pub block_count: u32,
    pub frame_size: u32,
    pub block_timeout_ms: u32,
}

pub struct NodeOptions {
    pub iface: String,
    pub workers: usize,
    pub fanout_group: Option<u16>,
    pub report_interval: Duration,
    pub report_natural: bool,
    pub ring: RingConfig,
    pub ignore_list: Option<PathBuf>,
    pub accept_source_list: Option<PathBuf>,
}

fn validate_ring_config(cfg: &RingConfig) -> Result<()> {
    if cfg.block_size == 0 || cfg.block_count == 0 || cfg.frame_size == 0 {
        return Err(anyhow!("ring parameters must be non-zero"));
    }
    if !cfg.block_size.is_multiple_of(cfg.frame_size) {
        return Err(anyhow!("block size must be a multiple of frame size"));
    }
    let alignment = libc::TPACKET_ALIGNMENT as u32;
    if !cfg.block_size.is_multiple_of(alignment) || !cfg.frame_size.is_multiple_of(alignment) {
        return Err(anyhow!(
            "block and frame sizes must be aligned to {} bytes",
            alignment
        ));
    }
    Ok(())
}

pub async fn run_packet_pipeline(opts: NodeOptions) -> Result<()> {
    if opts.workers == 0 {
        return Err(anyhow!("workers must be at least 1"));
    }
    if opts.report_interval.is_zero() {
        return Err(anyhow!("report interval must be greater than zero"));
    }
    validate_ring_config(&opts.ring)?;

    let ignore_list = Arc::new(AddressList::from_option(
        opts.ignore_list.as_deref(),
        "ignore list",
    )?);
    let accept_list = Arc::new(AddressList::from_option(
        opts.accept_source_list.as_deref(),
        "accept source list",
    )?);

    let counters = Arc::new(CounterTable::default());

    let running = Arc::new(AtomicBool::new(true));

    let mut handles = Vec::with_capacity(opts.workers);
    for worker_id in 0..opts.workers {
        let counters_clone = counters.clone();
        let running_clone = running.clone();
        let ctx = WorkerContext {
            iface: opts.iface.clone(),
            fanout_group: opts.fanout_group,
            ring_cfg: opts.ring,
            ignore_list: ignore_list.clone(),
            accept_list: accept_list.clone(),
        };
        handles.push(task::spawn(async move {
            worker_loop(worker_id, running_clone, counters_clone, ctx).await
        }));
    }

    let reporter_table = counters.clone();
    let reporter_running = running.clone();
    let report_interval = opts.report_interval;
    let report_natural = opts.report_natural;
    let reporter = tokio::spawn(async move {
        run_reporter(
            reporter_table,
            reporter_running,
            report_interval,
            report_natural,
        )
        .await;
    });

    signal::ctrl_c()
        .await
        .context("failed to wait for ctrl-c")?;
    println!("Received shutdown signal, draining...");
    running.store(false, Ordering::Relaxed);

    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(anyhow!("worker panicked: {err}")),
        }
    }

    reporter.abort();
    let _ = reporter.await;

    log_snapshot(&counters);
    Ok(())
}

struct WorkerContext {
    iface: String,
    fanout_group: Option<u16>,
    ring_cfg: RingConfig,
    ignore_list: Arc<AddressList>,
    accept_list: Arc<AddressList>,
}

async fn worker_loop(
    worker_id: usize,
    running: Arc<AtomicBool>,
    counters: Arc<CounterTable>,
    ctx: WorkerContext,
) -> Result<()> {
    let WorkerContext {
        iface,
        fanout_group,
        ring_cfg,
        ignore_list,
        accept_list,
    } = ctx;
    let mut socket = PacketSocket::bind(&iface, fanout_group, ring_cfg)
        .with_context(|| format!("worker {worker_id}: failed to bind packet socket"))?;
    socket
        .pump(&running, counters, &ignore_list, &accept_list)
        .await
}

struct PacketSocket {
    fd: OwnedFd,
    ring: PacketRing,
}

impl PacketSocket {
    fn bind(iface: &str, fanout_group: Option<u16>, ring_cfg: RingConfig) -> Result<Self> {
        let protocol = (libc::ETH_P_ALL as u16).to_be();
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                protocol as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("failed to create packet socket");
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let version: libc::c_int = libc::tpacket_versions::TPACKET_V3 as libc::c_int;
        let rc = unsafe {
            libc::setsockopt(
                owned_fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                mem::size_of_val(&version) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("failed to enable TPACKET_V3");
        }

        bind_interface(owned_fd.as_raw_fd(), iface, protocol)?;
        configure_fanout(owned_fd.as_raw_fd(), fanout_group)?;

        let ring = PacketRing::new(owned_fd.as_raw_fd(), ring_cfg)?;

        Ok(Self { fd: owned_fd, ring })
    }

    async fn pump(
        &mut self,
        running: &AtomicBool,
        counters: Arc<CounterTable>,
        ignore_list: &AddressList,
        accept_list: &AddressList,
    ) -> Result<()> {
        let block_nr = self.ring.block_count() as usize;
        while running.load(Ordering::Relaxed) {
            let mut made_progress = false;
            for _ in 0..block_nr {
                if self
                    .ring
                    .consume_next_block(&counters, ignore_list, accept_list)?
                {
                    made_progress = true;
                }
            }

            // If we didn't make any progress, wait for the socket to be readable
            if !made_progress {
                wait_for_read(self.fd.as_raw_fd()).await?;
            }
        }

        Ok(())
    }
}

fn bind_interface(fd: RawFd, iface: &str, protocol: u16) -> Result<()> {
    let ifname = CString::new(iface)?;
    let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error()).context("failed to lookup interface index");
    }

    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::c_ushort;
    addr.sll_protocol = protocol;
    addr.sll_ifindex = ifindex as libc::c_int;

    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("failed to bind packet socket");
    }

    Ok(())
}

fn configure_fanout(fd: RawFd, fanout_group: Option<u16>) -> Result<()> {
    if let Some(group) = fanout_group {
        let fanout_type = libc::PACKET_FANOUT_HASH;
        let val: u32 = (group as u32) | (fanout_type << 16);
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_FANOUT,
                &val as *const _ as *const libc::c_void,
                mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("failed to configure PACKET_FANOUT");
        }
    }

    Ok(())
}

struct PacketRing {
    base: *mut u8,
    len: usize,
    req: libc::tpacket_req3,
    current_block: u32,
}

// This is safe because each PacketRing is tied to a single PacketSocket, and each PacketSocket is
// only owned by a single thread.
unsafe impl Send for PacketRing {}
unsafe impl Sync for PacketRing {}

impl PacketRing {
    fn new(fd: RawFd, cfg: RingConfig) -> Result<Self> {
        if cfg.block_count == 0 {
            return Err(anyhow!("block count must be greater than zero"));
        }
        if cfg.block_size == 0 {
            return Err(anyhow!("block size must be greater than zero"));
        }
        if cfg.frame_size > cfg.block_size {
            return Err(anyhow!("frame size must be <= block size"));
        }
        let frames_per_block = cfg.block_size / cfg.frame_size;
        if frames_per_block == 0 {
            return Err(anyhow!("frame size does not fit within block"));
        }
        let frame_nr = frames_per_block
            .checked_mul(cfg.block_count)
            .ok_or_else(|| anyhow!("ring size overflow"))?;

        let req = libc::tpacket_req3 {
            tp_block_size: cfg.block_size,
            tp_block_nr: cfg.block_count,
            tp_frame_size: cfg.frame_size,
            tp_frame_nr: frame_nr,
            tp_retire_blk_tov: cfg.block_timeout_ms,
            tp_sizeof_priv: 0,
            tp_feature_req_word: libc::TP_FT_REQ_FILL_RXHASH,
        };

        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                mem::size_of::<libc::tpacket_req3>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("failed to configure PACKET_RX_RING");
        }

        let len = (req.tp_block_size as usize)
            .checked_mul(req.tp_block_nr as usize)
            .ok_or_else(|| anyhow!("ring mmap length overflow"))?;
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error()).context("failed to mmap PACKET_RX_RING");
        }

        Ok(Self {
            base: base as *mut u8,
            len,
            req,
            current_block: 0,
        })
    }

    fn block_count(&self) -> u32 {
        self.req.tp_block_nr
    }

    fn block_size(&self) -> usize {
        self.req.tp_block_size as usize
    }

    fn consume_next_block(
        &mut self,
        counters: &CounterTable,
        ignore_list: &AddressList,
        accept_list: &AddressList,
    ) -> Result<bool> {
        let idx = self.current_block;
        self.current_block = (self.current_block + 1) % self.req.tp_block_nr.max(1);
        self.consume_block(idx, counters, ignore_list, accept_list)
    }

    fn consume_block(
        &mut self,
        idx: u32,
        counters: &CounterTable,
        ignore_list: &AddressList,
        accept_list: &AddressList,
    ) -> Result<bool> {
        let block_ptr = unsafe { self.base.add(idx as usize * self.block_size()) };
        let desc = block_ptr as *mut libc::tpacket_block_desc;
        let status = unsafe { (*desc).hdr.bh1.block_status };
        if status & libc::TP_STATUS_USER == 0 {
            return Ok(false);
        }

        fence(Ordering::Acquire);
        unsafe {
            let ignore_is_empty = ignore_list.is_empty();
            let accept_is_empty = accept_list.is_empty();
            let hdr = &mut (*desc).hdr.bh1;
            let mut offset = hdr.offset_to_first_pkt as usize;
            let block_size = self.block_size();
            for _ in 0..hdr.num_pkts {
                if offset >= block_size {
                    break;
                }
                let frame_ptr = block_ptr.add(offset) as *mut libc::tpacket3_hdr;
                let next = (*frame_ptr).tp_next_offset as usize;
                let snaplen = (*frame_ptr).tp_snaplen as usize;
                let packet_len = (*frame_ptr).tp_len as usize;
                let mac = (*frame_ptr).tp_mac as usize;
                if snaplen == 0 {
                    break;
                }
                let data_offset = offset + mac;
                if data_offset >= block_size || data_offset + snaplen > block_size {
                    break;
                }
                let data = slice::from_raw_parts(block_ptr.add(data_offset), snaplen);
                if let Some(flow) = extract_flow(data) {
                    let bytes = packet_len as u64;
                    let packets = 1;
                    //TODO: check if this packet is being received by us or being transmitted by us
                    // We can do this check by looking at the packet's src and dst.
                    // If it's a packet being received by us, the dst IP should match one of our local IPs.
                    // Otherwise, it's a transmitted packet.
                    // Then, we decide if we should increment rx or tx counters accordingly, and should take
                    // ignore/accept lists into account properly.
                    let dst_allowed = ignore_is_empty || !ignore_list.contains(&flow.remote_ip);
                    let src_allowed = accept_is_empty || accept_list.contains(&flow.local_ip);
                    if dst_allowed && src_allowed {
                        counters.increment_tx(flow, bytes, packets);
                    }
                }
                if next == 0 {
                    break;
                }
                offset += next;
            }
            hdr.block_status = libc::TP_STATUS_KERNEL;
        }
        fence(Ordering::Release);
        Ok(true)
    }
}

impl Drop for PacketRing {
    fn drop(&mut self) {
        if !self.base.is_null() && self.len > 0 {
            unsafe {
                libc::munmap(self.base as *mut libc::c_void, self.len);
            }
        }
    }
}

async fn wait_for_read(fd: RawFd) -> Result<()> {
    use tokio::io::unix::AsyncFd;

    let async_fd = AsyncFd::new(fd).context("failed to create AsyncFd")?;
    loop {
        let mut guard = async_fd
            .readable()
            .await
            .context("failed to wait for socket readability")?;
        match guard.try_io(|_| Ok(())) {
            Ok(result) => {
                result?;
                return Ok(());
            }
            Err(_would_block) => continue,
        }
    }
}

async fn run_reporter(
    table: Arc<CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
    natural: bool,
) {
    if natural {
        run_natural_reporter(table, running, interval).await;
    } else {
        run_interval_reporter(table, running, interval).await;
    }
}

async fn run_interval_reporter(
    table: Arc<CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
) {
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        if !running.load(Ordering::Relaxed) {
            break;
        }
        log_snapshot(&table);
    }
}

async fn run_natural_reporter(
    table: Arc<CounterTable>,
    running: Arc<AtomicBool>,
    interval: Duration,
) {
    loop {
        let wait = duration_until_next_boundary(interval);
        time::sleep(wait).await;
        if !running.load(Ordering::Relaxed) {
            break;
        }
        log_snapshot(&table);
    }
}

fn duration_until_next_boundary(interval: Duration) -> Duration {
    if interval.is_zero() {
        return Duration::from_secs(0);
    }
    let now = SystemTime::now();
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let interval_ns = interval.as_nanos();
    if interval_ns == 0 {
        return Duration::from_secs(0);
    }
    let since_ns = since_epoch.as_nanos();
    let next_multiple = ((since_ns / interval_ns) + 1) * interval_ns;
    let wait_ns = next_multiple - since_ns;
    nanos_to_duration(wait_ns)
}

fn nanos_to_duration(ns: u128) -> Duration {
    const NS_PER_SEC: u128 = 1_000_000_000;
    let secs = (ns / NS_PER_SEC) as u64;
    let nanos = (ns % NS_PER_SEC) as u32;
    Duration::new(secs, nanos)
}

fn extract_flow(frame: &[u8]) -> Option<crate::model::Flow> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }

    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = ETH_HEADER_LEN;
    const VLAN_TAGS: [u16; 3] = [0x8100, 0x88A8, 0x9100];

    while VLAN_TAGS.contains(&ethertype) {
        if frame.len() < offset + 4 {
            return None;
        }
        // VLAN header is 4 bytes: TCI + encapsulated ethertype.
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    let segment = frame.get(offset..)?;
    match ethertype {
        ETH_P_IPV4 | ETH_P_IPV6 => parse_segment(segment),
        _ => None,
    }
}

fn parse_segment(segment: &[u8]) -> Option<crate::model::Flow> {
    if segment.is_empty() {
        return None;
    }
    let version = segment[0] >> 4;
    match version {
        4 => parse_ipv4_flow(segment),
        6 => parse_ipv6_flow(segment),
        _ => None,
    }
}

fn parse_ipv4_flow(segment: &[u8]) -> Option<crate::model::Flow> {
    if segment.len() < IPV4_MIN_HEADER {
        return None;
    }
    let ihl = ((segment[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HEADER || segment.len() < ihl {
        return None;
    }
    let proto = segment[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        segment[12],
        segment[13],
        segment[14],
        segment[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        segment[16],
        segment[17],
        segment[18],
        segment[19],
    ));
    let (src_port, dst_port) = parse_ports(proto, &segment[ihl..]);
    Some(crate::model::Flow {
        local_ip: src_ip,
        remote_ip: dst_ip,
        local_port: src_port,
        remote_port: dst_port,
        protocol: proto,
    })
}

fn parse_ipv6_flow(segment: &[u8]) -> Option<crate::model::Flow> {
    if segment.len() < IPV6_HEADER_LEN {
        return None;
    }
    let proto = segment[6];
    let src_ip = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([segment[8], segment[9]]),
        u16::from_be_bytes([segment[10], segment[11]]),
        u16::from_be_bytes([segment[12], segment[13]]),
        u16::from_be_bytes([segment[14], segment[15]]),
        u16::from_be_bytes([segment[16], segment[17]]),
        u16::from_be_bytes([segment[18], segment[19]]),
        u16::from_be_bytes([segment[20], segment[21]]),
        u16::from_be_bytes([segment[22], segment[23]]),
    ));
    let dst_ip = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([segment[24], segment[25]]),
        u16::from_be_bytes([segment[26], segment[27]]),
        u16::from_be_bytes([segment[28], segment[29]]),
        u16::from_be_bytes([segment[30], segment[31]]),
        u16::from_be_bytes([segment[32], segment[33]]),
        u16::from_be_bytes([segment[34], segment[35]]),
        u16::from_be_bytes([segment[36], segment[37]]),
        u16::from_be_bytes([segment[38], segment[39]]),
    ));
    let payload = &segment[IPV6_HEADER_LEN..];
    let (src_port, dst_port) = parse_ports(proto, payload);
    Some(crate::model::Flow {
        local_ip: src_ip,
        remote_ip: dst_ip,
        local_port: src_port,
        remote_port: dst_port,
        protocol: proto,
    })
}

fn parse_ports(proto: u8, payload: &[u8]) -> (u16, u16) {
    if payload.len() < 4 {
        return (0, 0);
    }
    match proto {
        6 | 17 => {
            let src = u16::from_be_bytes([payload[0], payload[1]]);
            let dst = u16::from_be_bytes([payload[2], payload[3]]);
            (src, dst)
        }
        _ => (0, 0),
    }
}
