use std::{
    ffi::CString,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr, slice,
    sync::atomic::{AtomicBool, Ordering, fence},
};

use anyhow::{Context, Result, anyhow};
use tokio::io::unix::AsyncFd;

use crate::model::AddressList;
use crate::traffic::{L4Meta, L4Traffic};

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

#[derive(Clone, Copy, Debug)]
pub struct RingConfig {
    pub block_size: u32,
    pub block_count: u32,
    pub frame_size: u32,
    pub block_timeout_ms: u32,
}

pub fn validate_ring_config(cfg: &RingConfig) -> Result<()> {
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

pub struct PacketSocket {
    fd: OwnedFd,
    ring: PacketRing,
}

impl PacketSocket {
    pub fn bind(iface: &str, fanout_group: Option<u16>, ring_cfg: RingConfig) -> Result<Self> {
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

    pub async fn pump<F, Fut>(
        &mut self,
        running: &AtomicBool,
        remote_whitelist: &AddressList,
        local_addresslist: &AddressList,
        mut on_traffic: F,
    ) -> Result<()>
    where
        F: FnMut(L4Meta, L4Traffic) -> Fut + Send,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let block_nr = self.ring.block_count() as usize;
        while running.load(Ordering::Relaxed) {
            let mut made_progress = false;
            for _ in 0..block_nr {
                if self
                    .ring
                    .consume_next_block(remote_whitelist, local_addresslist, &mut on_traffic)
                    .await?
                {
                    made_progress = true;
                }
            }

            if !made_progress {
                wait_for_read(self.fd.as_raw_fd()).await?;
            }
        }

        Ok(())
    }
}

struct PacketRing {
    base: *mut u8,
    len: usize,
    req: libc::tpacket_req3,
    current_block: u32,
}

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

    async fn consume_next_block<F, Fut>(
        &mut self,
        remote_whitelist: &AddressList,
        local_addresslist: &AddressList,
        on_traffic: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(L4Meta, L4Traffic) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let idx = self.current_block;
        self.current_block = (self.current_block + 1) % self.req.tp_block_nr.max(1);
        self.consume_block(idx, remote_whitelist, local_addresslist, on_traffic)
            .await
    }

    async fn consume_block<F, Fut>(
        &mut self,
        idx: u32,
        remote_whitelist: &AddressList,
        local_addresslist: &AddressList,
        on_traffic: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(L4Meta, L4Traffic) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        // 1. Check status and get loop bounds.
        // We do this in a block to ensure `desc` and `block_ptr` are not held.
        let (num_pkts, mut offset) = {
            let block_ptr = unsafe { self.base.add(idx as usize * self.block_size()) };
            let desc = block_ptr as *mut libc::tpacket_block_desc;
            let status = unsafe { ptr::read_volatile(&((*desc).hdr.bh1.block_status)) };
            if status & libc::TP_STATUS_USER == 0 {
                return Ok(false);
            }
            fence(Ordering::Acquire);
            unsafe {
                let hdr = &(*desc).hdr.bh1;
                (hdr.num_pkts, hdr.offset_to_first_pkt as usize)
            }
        };

        let remote_whitelist_empty = remote_whitelist.is_empty();
        let local_addresslist_empty = local_addresslist.is_empty();
        let block_size = self.block_size();

        // Base address for recalculating pointers inside the loop.
        // self.base is *mut u8, which is not Send, but we access it via self (which is &mut self, not Send across await if self is held... wait).
        // self is held across await because we call on_traffic which is `&mut F`.
        // But `self.base` is just a field.
        // The issue is that the async state machine captures local variables.
        // Previous error said `block_ptr` (local var) was not Send.
        // By not having `block_ptr` in the outer scope, we should be safe.
        // But we need `block_ptr` inside the loop. We can recompute it from `self.base`.
        // `self` is `&mut PacketRing`. `PacketRing` is `Send`. `&mut PacketRing` is `Send`.
        // So accessing `self.base` inside the loop (between awaits) is fine.

        for _ in 0..num_pkts {
            if offset >= block_size {
                break;
            }

            // Recompute block_ptr here.
            // We need to ensure nothing derived from it lives across await.
            let (next, traffic_opt) = {
                let block_ptr = unsafe { self.base.add(idx as usize * self.block_size()) };
                unsafe {
                    let frame_ptr = block_ptr.add(offset) as *mut libc::tpacket3_hdr;
                    let next = (*frame_ptr).tp_next_offset as usize;
                    let snaplen = (*frame_ptr).tp_snaplen as usize;
                    let packet_len = (*frame_ptr).tp_len as usize;
                    let mac = (*frame_ptr).tp_mac as usize;

                    if snaplen == 0 {
                        (0, None)
                    } else {
                        let data_offset = offset + mac;
                        if data_offset >= block_size || data_offset + snaplen > block_size {
                            (next, None)
                        } else {
                            let data = slice::from_raw_parts(block_ptr.add(data_offset), snaplen);
                            if let Some(l4_meta) = extract_l4_meta(data) {
                                let bytes = packet_len as u64;
                                let packets = 1;
                                let traffic = L4Traffic {
                                    l4_meta,
                                    rx_bytes: 0,
                                    rx_packets: 0,
                                    tx_bytes: bytes,
                                    tx_packets: packets,
                                };
                                (next, Some((l4_meta, traffic)))
                            } else {
                                (next, None)
                            }
                        }
                    }
                }
            };

            // Now await. No raw pointers are in scope here.
            if let Some((l4_meta, traffic)) = traffic_opt {
                let dst_allowed =
                    remote_whitelist_empty || !remote_whitelist.contains(&l4_meta.remote_ip);
                let src_allowed =
                    local_addresslist_empty || local_addresslist.contains(&l4_meta.local_ip);

                if dst_allowed && src_allowed {
                    on_traffic(l4_meta, traffic).await;
                }
            }

            if next == 0 {
                break;
            }
            offset += next;
        }

        {
            let block_ptr = unsafe { self.base.add(idx as usize * self.block_size()) };
            let desc = block_ptr as *mut libc::tpacket_block_desc;
            unsafe {
                ptr::write_volatile(&mut (*desc).hdr.bh1.block_status, libc::TP_STATUS_KERNEL);
            }
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

fn extract_l4_meta(frame: &[u8]) -> Option<L4Meta> {
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
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    let segment = frame.get(offset..)?;
    match ethertype {
        ETH_P_IPV4 | ETH_P_IPV6 => parse_segment(segment),
        _ => None,
    }
}

fn parse_segment(segment: &[u8]) -> Option<L4Meta> {
    if segment.is_empty() {
        return None;
    }
    let version = segment[0] >> 4;
    match version {
        4 => parse_ipv4_meta(segment),
        6 => parse_ipv6_meta(segment),
        _ => None,
    }
}

fn parse_ipv4_meta(segment: &[u8]) -> Option<L4Meta> {
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
    Some(L4Meta {
        local_ip: src_ip,
        remote_ip: dst_ip,
        local_port: src_port,
        remote_port: dst_port,
        protocol: proto,
    })
}

fn parse_ipv6_meta(segment: &[u8]) -> Option<L4Meta> {
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
    Some(L4Meta {
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
