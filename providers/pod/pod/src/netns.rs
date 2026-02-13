use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// A discovered network namespace entry tied to a process.
#[derive(Debug, Clone)]
pub struct NetnsEntry {
    pub pid: i32,
    pub path: PathBuf,
    pub inode: u64,
}

/// Guard that switches into a target network namespace and restores the original on drop.
pub struct NetnsGuard {
    original: File,
}

impl NetnsGuard {
    /// Enter the network namespace identified by `netns_path`.
    /// The returned guard will restore the original namespace on drop.
    pub fn enter(netns_path: &Path) -> Result<Self> {
        let original = File::open("/proc/self/ns/net").context("open current netns")?;
        let target = File::open(netns_path)
            .with_context(|| format!("open target netns {}", netns_path.display()))?;
        setns(target.as_raw_fd())?;
        Ok(Self { original })
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = setns(self.original.as_raw_fd());
    }
}

/// Discover pod network namespaces by scanning `/proc` and selecting processes
/// whose cgroup path indicates a Kubernetes pod (kubepods).
///
/// This returns unique namespaces by inode to avoid duplicate work across PIDs.
pub fn discover_pod_netns() -> Result<Vec<NetnsEntry>> {
    let mut entries = Vec::new();
    let mut seen_inodes = HashSet::new();

    for proc_entry in fs::read_dir("/proc").context("read /proc")? {
        let proc_entry = match proc_entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let file_name = proc_entry.file_name();
        let pid_str = file_name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };

        let cgroup_path = proc_entry.path().join("cgroup");
        let Ok(cgroup_contents) = fs::read_to_string(&cgroup_path) else {
            continue;
        };

        if !is_kubernetes_pod_cgroup(&cgroup_contents) {
            continue;
        }

        let netns_path = proc_entry.path().join("ns/net");
        let inode = match read_netns_inode(&netns_path) {
            Ok(inode) => inode,
            Err(_) => continue,
        };

        if seen_inodes.insert(inode) {
            entries.push(NetnsEntry {
                pid,
                path: netns_path,
                inode,
            });
        }
    }

    Ok(entries)
}

/// Check whether the current namespace has an `eth0` interface.
pub fn current_netns_has_eth0() -> bool {
    Path::new("/sys/class/net/eth0").exists()
}

fn is_kubernetes_pod_cgroup(cgroup_contents: &str) -> bool {
    // Common in both cgroup v1 and v2 setups.
    cgroup_contents.contains("kubepods")
}

fn read_netns_inode(netns_path: &Path) -> Result<u64> {
    let link =
        fs::read_link(netns_path).with_context(|| format!("readlink {}", netns_path.display()))?;
    let link_str = link.to_string_lossy();
    // Expected format: "net:[4026531993]"
    let inode = link_str
        .strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .context("unexpected netns link format")?
        .parse::<u64>()
        .context("parse netns inode")?;
    Ok(inode)
}

fn setns(fd: i32) -> Result<()> {
    let ret = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        return Err(anyhow::anyhow!("setns(CLONE_NEWNET) failed: {}", err));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn kubernetes_cgroup_detection() {
        assert!(is_kubernetes_pod_cgroup(
            "0::/kubepods.slice/kubepods-besteffort.slice"
        ));
        assert!(!is_kubernetes_pod_cgroup("0::/user.slice/user-1000.slice"));
    }

    #[test]
    fn read_netns_inode_parses_link() {
        let base = std::env::temp_dir().join(format!("tc-netns-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let link_path = base.join("net");
        symlink("net:[4026531993]", &link_path).unwrap();

        let inode = read_netns_inode(&link_path).unwrap();
        assert_eq!(inode, 4026531993);

        fs::remove_dir_all(&base).unwrap();
    }
}
