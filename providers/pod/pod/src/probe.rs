use aya::{
    maps::MapType,
    sys::{SyscallError, is_map_supported},
};
use tracing::warn;

pub fn probe_ringbuf_support() -> Result<bool, SyscallError> {
    is_map_supported(MapType::RingBuf)
}

pub fn probe_perf_event_array_support() -> Result<bool, SyscallError> {
    is_map_supported(MapType::PerfEventArray)
}

pub fn probe_tcx_support() -> bool {
    // BPF link support for tc programs was added in Linux 6.6, so we can check the kernel version.
    // However, this is not a perfect check, as some distributions backport features to older kernels.
    // For simplicity, we will just check the kernel version here.
    let kernel_version = match aya::util::KernelVersion::current() {
        Ok(version) => version,
        Err(e) => {
            warn!("Failed to get kernel version: {e}, assuming bpf_link is not supported");
            return false;
        }
    };
    kernel_version >= aya::util::KernelVersion::new(6, 6, 0)
}

pub fn probe_memcg_based_accounting_support() -> bool {
    // Memcg based accounting was added in Linux 5.11, so we can check the kernel version.
    let kernel_version = match aya::util::KernelVersion::current() {
        Ok(version) => version,
        Err(e) => {
            warn!(
                "Failed to get kernel version: {e}, assuming memcg based accounting is not supported"
            );
            return false;
        }
    };
    kernel_version >= aya::util::KernelVersion::new(5, 11, 0)
}
