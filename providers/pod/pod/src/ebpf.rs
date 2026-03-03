use anyhow::{Result, anyhow};
use aya::programs::{
    LinkOrder, SchedClassifier, TcAttachType, loaded_programs,
    tc::{NlOptions, TcAttachOptions, TcError, qdisc_detach_program},
};
use pod_provider_common::Direction;
use std::io;
use tracing::{debug, info};

use crate::probe::probe_tcx_support;

pub trait Attacher {
    fn attach(&self, prog: &mut SchedClassifier, iface: &str, dir: TcAttachType) -> Result<()>;
    // fn detach(prog: &mut SchedClassifier, iface: &str, dir: TcAttachType) -> Result<()>;
}
#[derive(Default)]
struct NetlinkAttacher {}

impl NetlinkAttacher {
    // This function cleans up any leftover programs from previous program runs based on program name prefix.
    // If a program with the same name is found, it will be detached and removed.
    // This function exists to ensure that there are no leftover programs from previous runs that may interfere with the current program.
    fn cleanup(&self, iface: &str) -> Result<()> {
        for program in loaded_programs() {
            let program = program?;
            let name = match program.name_as_str() {
                Some(name) if name.starts_with(pod_provider_common::PROGRAM_NAME_PREFIX) => name,
                _ => continue,
            };
            for attach_type in [TcAttachType::Ingress, TcAttachType::Egress] {
                match qdisc_detach_program(iface, attach_type, name) {
                    Ok(()) => {
                        debug!("Detached leftover tc program {name} on {iface} ({attach_type:?})");
                    }
                    Err(TcError::IoError(err)) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(anyhow!(
                            "failed to detach leftover tc program {name} on {iface} ({attach_type:?}): {err}"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl Attacher for NetlinkAttacher {
    fn attach(&self, prog: &mut SchedClassifier, iface: &str, dir: TcAttachType) -> Result<()> {
        debug!(
            "Attaching program using netlink, cleaning up any leftover programs from previous runs"
        );
        self.cleanup(iface)?;
        // Currently the priority and the handle are set to default values, which means the kernel chooses the highest priority available for the program.
        // and the handle will be automatically assigned by the kernel.
        // Ref: https://docs.rs/aya/latest/aya/programs/tc/struct.NlOptions.html
        // In the future, we may want to allow users to specify these values for more fine-grained control over the program attachment.
        let options = TcAttachOptions::Netlink(NlOptions::default());
        let _ = prog
            .attach_with_options(iface, dir, options)
            .or_else(|e| Err(anyhow!("failed to attach the program using netlink: {e}")))?;
        debug!("Program attached successfully using netlink");
        Ok(())
    }
}
#[derive(Default)]
struct BpfLinkAttacher {}

impl Attacher for BpfLinkAttacher {
    fn attach(&self, prog: &mut SchedClassifier, iface: &str, dir: TcAttachType) -> Result<()> {
        debug!("Attaching program using bpf_link");
        // Currently the order is set to default value, which means the program will be attached last.
        // Ref: https://docs.rs/aya/latest/aya/programs/links/struct.LinkOrder.html#impl-Default-for-LinkOrder
        let options = TcAttachOptions::TcxOrder(LinkOrder::default());
        let _ = prog
            .attach_with_options(iface, dir, options)
            .or_else(|e| Err(anyhow!("failed to attach the program using bpf_link: {e}")))?;
        debug!("Program attached successfully using bpf_link");
        Ok(())
    }
}

enum TcAttacher {
    NETLINK(NetlinkAttacher),
    BPFLINK(BpfLinkAttacher),
}

impl Attacher for TcAttacher {
    fn attach(&self, prog: &mut SchedClassifier, iface: &str, dir: TcAttachType) -> Result<()> {
        match self {
            TcAttacher::NETLINK(attacher) => attacher.attach(prog, iface, dir),
            TcAttacher::BPFLINK(attacher) => attacher.attach(prog, iface, dir),
        }
    }
}

/// Manages TC attachments without owning program instances.
pub struct EbpfManager {
    attacher: TcAttacher,
}

impl EbpfManager {
    pub fn new() -> Result<Self> {
        let attacher = if probe_tcx_support() {
            info!("Kernel supports bpf_link, using bpf_link for program attachment");
            TcAttacher::BPFLINK(BpfLinkAttacher::default())
        } else {
            info!("Kernel does not support bpf_link, using netlink for program attachment");
            TcAttacher::NETLINK(NetlinkAttacher::default())
        };
        Ok(Self { attacher })
    }

    /*
    pub fn load_programs(
        &self,
        ingress_prog: &mut SchedClassifier,
        egress_prog: &mut SchedClassifier,
    ) -> Result<()> {
        debug!("Loading eBPF programs");
        ingress_prog.load()?;
        egress_prog.load()?;
        debug!("eBPF programs loaded successfully");
        Ok(())
    }
    */

    pub fn load_program(&self, prog: &mut SchedClassifier) -> Result<()> {
        debug!("Loading eBPF program");
        prog.load()?;
        debug!("eBPF program loaded successfully");
        Ok(())
    }

    pub fn attach(&self, prog: &mut SchedClassifier, iface: &str, dir: Direction) -> Result<()> {
        match dir {
            Direction::Ingress => self.attacher.attach(prog, iface, TcAttachType::Ingress),
            Direction::Egress => self.attacher.attach(prog, iface, TcAttachType::Egress),
        }
    }
}
