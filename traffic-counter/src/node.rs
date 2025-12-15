use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    ffi::CString,
    fs::File,
    hash::{Hash, Hasher},
    io::{self, BufRead, BufReader},
    mem,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::{Path, PathBuf},
    ptr, slice,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering, fence},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use tokio::{signal, task, time};

use traffic_counter_common::{Counters, IpKey};

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const COUNTER_SHARDS: usize = 64;

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
    pub ring: RingConfig,
    pub ignore_list: Option<PathBuf>,
}

struct IgnoreList {
    entries: HashSet<IpKey>,
}

impl IgnoreList {
    fn empty() -> Self {
        Self {
            entries: HashSet::new(),
        }
    }

    fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open ignore list at {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut entries = HashSet::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!(
                    "failed to read line {} of ignore list {}",
                    line_no + 1,
                    path.display()
                )
            })?;
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let addr: IpAddr = trimmed.parse().with_context(|| {
                format!(
                    "invalid IP address '{}' on line {} of {}",
                    trimmed,
                    line_no + 1,
                    path.display()
                )
            })?;
            entries.insert(ipaddr_to_key(addr));
        }

        Ok(Self { entries })
    }

    fn contains(&self, key: &IpKey) -> bool {
        self.entries.contains(key)
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn ipaddr_to_key(addr: IpAddr) -> IpKey {
    match addr {
        IpAddr::V4(v4) => {
            let raw = u32::from_be_bytes(v4.octets());
            IpKey {
                family: libc::AF_INET as u8,
                pad: [0; 7],
                addr_lo: raw as u64,
                addr_hi: 0,
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let addr_hi = u64::from_be_bytes(octets[0..8].try_into().expect("slice sized"));
            let addr_lo = u64::from_be_bytes(octets[8..16].try_into().expect("slice sized"));
            IpKey {
                family: libc::AF_INET6 as u8,
                pad: [0; 7],
                addr_lo,
                addr_hi,
            }
        }
    }
}

fn validate_ring_config(cfg: &RingConfig) -> Result<()> {
    if cfg.block_size == 0 || cfg.block_count == 0 || cfg.frame_size == 0 {
        return Err(anyhow!("ring parameters must be non-zero"));
    }
    if cfg.block_size % cfg.frame_size != 0 {
        return Err(anyhow!("block size must be a multiple of frame size"));
    }
    let alignment = libc::TPACKET_ALIGNMENT as u32;
    if cfg.block_size % alignment != 0 || cfg.frame_size % alignment != 0 {
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

    let ignore_list = Arc::new(match opts.ignore_list.as_ref() {
        Some(path) => IgnoreList::from_path(path)?,
        None => IgnoreList::empty(),
    });

    let counters = Arc::new(CounterTable::default());

    let running = Arc::new(AtomicBool::new(true));

    let mut handles = Vec::with_capacity(opts.workers);
    for worker_id in 0..opts.workers {
        let iface = opts.iface.clone();
        let fanout = opts.fanout_group;
        let counters_clone = counters.clone();
        let running_clone = running.clone();
        let ring_cfg = opts.ring;
        let ignore_clone = ignore_list.clone();
        handles.push(task::spawn(async move {
            worker_loop(
                worker_id,
                &iface,
                fanout,
                running_clone,
                counters_clone,
                ring_cfg,
                ignore_clone,
            )
            .await
        }));
    }

    let reporter_table = counters.clone();
    let reporter_running = running.clone();
    let report_interval = opts.report_interval;
    let reporter = tokio::spawn(async move {
        let mut ticker = time::interval(report_interval);
        loop {
            ticker.tick().await;
            if !reporter_running.load(Ordering::Relaxed) {
                break;
            }
            log_snapshot(&reporter_table);
        }
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

async fn worker_loop(
    worker_id: usize,
    iface: &str,
    fanout_group: Option<u16>,
    running: Arc<AtomicBool>,
    counters: Arc<CounterTable>,
    ring_cfg: RingConfig,
    ignore_list: Arc<IgnoreList>,
) -> Result<()> {
    let mut socket = PacketSocket::bind(iface, fanout_group, ring_cfg)
        .with_context(|| format!("worker {worker_id}: failed to bind packet socket"))?;
    socket.pump(&running, counters, &ignore_list).await
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
        ignore_list: &IgnoreList,
    ) -> Result<()> {
        let block_nr = self.ring.block_count() as usize;
        while running.load(Ordering::Relaxed) {
            let mut made_progress = false;
            for _ in 0..block_nr {
                if self.ring.consume_next_block(&counters, ignore_list)? {
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
        if frame_nr > u32::MAX {
            return Err(anyhow!("ring frame count exceeds u32::MAX"));
        }

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
        ignore_list: &IgnoreList,
    ) -> Result<bool> {
        let idx = self.current_block;
        self.current_block = (self.current_block + 1) % self.req.tp_block_nr.max(1);
        self.consume_block(idx, counters, ignore_list)
    }

    fn consume_block(
        &mut self,
        idx: u32,
        counters: &CounterTable,
        ignore_list: &IgnoreList,
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
                if let Some(addrs) = parse_frame(data) {
                    if ignore_is_empty || !ignore_list.contains(&addrs.dst) {
                        counters.increment(addrs.src, packet_len as u64);
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

struct PacketAddrs {
    src: IpKey,
    dst: IpKey,
}

fn parse_frame(frame: &[u8]) -> Option<PacketAddrs> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    match ether_type {
        ETH_P_IPV4 => parse_ipv4(&frame[ETH_HEADER_LEN..]),
        ETH_P_IPV6 => parse_ipv6(&frame[ETH_HEADER_LEN..]),
        _ => None,
    }
}

fn parse_ipv4(payload: &[u8]) -> Option<PacketAddrs> {
    if payload.len() < IPV4_MIN_HEADER {
        return None;
    }
    let version_ihl = payload[0];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl_bytes = ((version_ihl & 0x0f) as usize) * 4;
    if payload.len() < ihl_bytes || ihl_bytes < IPV4_MIN_HEADER {
        return None;
    }
    let src = u32::from_be_bytes(payload[12..16].try_into().ok()?);
    let dst = u32::from_be_bytes(payload[16..20].try_into().ok()?);
    Some(PacketAddrs {
        src: IpKey {
            family: libc::AF_INET as u8,
            pad: [0; 7],
            addr_lo: src as u64,
            addr_hi: 0,
        },
        dst: IpKey {
            family: libc::AF_INET as u8,
            pad: [0; 7],
            addr_lo: dst as u64,
            addr_hi: 0,
        },
    })
}

fn parse_ipv6(payload: &[u8]) -> Option<PacketAddrs> {
    if payload.len() < IPV6_HEADER_LEN {
        return None;
    }
    let src_hi = u64::from_be_bytes(payload[8..16].try_into().ok()?);
    let src_lo = u64::from_be_bytes(payload[16..24].try_into().ok()?);
    let dst_hi = u64::from_be_bytes(payload[24..32].try_into().ok()?);
    let dst_lo = u64::from_be_bytes(payload[32..40].try_into().ok()?);
    Some(PacketAddrs {
        src: IpKey {
            family: libc::AF_INET6 as u8,
            pad: [0; 7],
            addr_lo: src_lo,
            addr_hi: src_hi,
        },
        dst: IpKey {
            family: libc::AF_INET6 as u8,
            pad: [0; 7],
            addr_lo: dst_lo,
            addr_hi: dst_hi,
        },
    })
}

struct CounterTable {
    shards: Vec<Mutex<HashMap<IpKey, Counters>>>,
}

impl CounterTable {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(COUNTER_SHARDS);
        for _ in 0..COUNTER_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self { shards }
    }

    fn shard_index(&self, key: &IpKey) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len().max(1)
    }

    fn increment(&self, key: IpKey, bytes: u64) {
        let idx = self.shard_index(&key);
        let mut guard = self.shards[idx]
            .lock()
            .expect("counter shard mutex poisoned");
        let entry = guard.entry(key).or_insert(Counters {
            bytes: 0,
            packets: 0,
        });
        entry.bytes = entry.bytes.wrapping_add(bytes);
        entry.packets = entry.packets.wrapping_add(1);
    }

    /*
    fn snapshot(&self) -> HashMap<IpKey, Counters> {
        let mut merged = HashMap::new();
        for shard in &self.shards {
            let guard = shard.lock().expect("counter shard mutex poisoned");
            for (key, counters) in guard.iter() {
                merged.insert(*key, *counters);
            }
        }
        merged
    }
    */

    fn snapshot_shard(&self, shard_idx: usize) -> HashMap<IpKey, Counters> {
        let mut snapshot = HashMap::new();
        if shard_idx < self.shards.len() {
            let mut guard = self.shards[shard_idx]
                .lock()
                .expect("counter shard mutex poisoned");
            for (key, counters) in guard.iter() {
                snapshot.insert(*key, *counters);
            }
            guard.clear();
        }
        snapshot
    }
}

impl Default for CounterTable {
    fn default() -> Self {
        Self::new()
    }
}

fn log_snapshot(table: &CounterTable) {
    for shard_idx in 0..table.shards.len() {
        let snapshot = table.snapshot_shard(shard_idx);
        for (ip, counters) in &snapshot {
            println!(
                "IP {:?} - bytes: {} packets: {}",
                ipkey2string(ip),
                counters.bytes,
                counters.packets
            );
        }
    }
}

fn ipkey2string(key: &IpKey) -> String {
    match key.family as i32 {
        libc::AF_INET => {
            let raw = (key.addr_lo & 0xFFFFFFFF) as u32;
            let octets = raw.to_be_bytes();
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
        }
        libc::AF_INET6 => {
            let hi_bytes = key.addr_hi.to_be_bytes();
            let lo_bytes = key.addr_lo.to_be_bytes();
            let segments: Vec<String> = hi_bytes
                .chunks(2)
                .chain(lo_bytes.chunks(2))
                .map(|chunk| {
                    let seg = u16::from_be_bytes([chunk[0], chunk[1]]);
                    format!("{:x}", seg)
                })
                .collect();
            segments.join(":")
        }
        _ => "unknown".to_string(),
    }
}
