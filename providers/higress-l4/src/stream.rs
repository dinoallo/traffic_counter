use proxy_wasm::hostcalls::get_property;
use proxy_wasm::traits::{Context, StreamContext};
use proxy_wasm::types::Action;

use crate::PLUGIN_NAME;
use crate::log::Log;

pub struct StreamHandler {
    log: Log,
    bytes_in: usize,
    bytes_out: usize,
    upstream_address: String,
    upstream_port: u16,
    downstream_remote_address: String,
    downstream_remote_port: u16,
}

impl StreamHandler {
    pub fn new() -> Self {
        StreamHandler {
            //TODO: pass log from root context or use a different name for log of stream context
            log: Log::new(PLUGIN_NAME.to_string()),
            bytes_in: 0,
            bytes_out: 0,
            upstream_address: String::new(),
            upstream_port: 0,
            downstream_remote_address: String::new(),
            downstream_remote_port: 0,
        }
    }
    fn log_bytes_in(&self) {
        self.log.info(&format!(
            "Upstream {}:{} received {} bytes",
            self.upstream_address, self.upstream_port, self.bytes_in,
        ));
    }
    fn log_bytes_out(&self) {
        self.log.info(&format!(
            "Downstream {}:{} sent {} bytes",
            self.downstream_remote_address, self.downstream_remote_port, self.bytes_out,
        ));
    }
}

impl Default for StreamHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Context for StreamHandler {}

impl StreamContext for StreamHandler {
    fn on_downstream_data(&mut self, data_size: usize, _end_of_stream: bool) -> Action {
        self.downstream_remote_address = match get_downstream_remote_address() {
            Some(addr) => addr,
            None => {
                self.log.error("Failed to get downstream remote address");
                return Action::Continue;
            }
        };
        self.downstream_remote_port = match get_downstream_remote_port() {
            Some(port) => port,
            None => {
                self.log.error("Failed to get downstream remote port");
                return Action::Continue;
            }
        };
        self.bytes_in += data_size;
        if _end_of_stream {
            self.log_bytes_out();
        }
        Action::Continue
    }

    fn on_upstream_data(&mut self, data_size: usize, _end_of_stream: bool) -> Action {
        self.upstream_address = match get_upstream_address() {
            Some(addr) => addr,
            None => {
                self.log.error("Failed to get upstream address");
                return Action::Continue;
            }
        };
        self.upstream_port = match get_upstream_port() {
            Some(port) => port,
            None => {
                self.log.error("Failed to get upstream port");
                return Action::Continue;
            }
        };
        self.bytes_out += data_size;
        if _end_of_stream {
            self.log_bytes_in();
        }
        Action::Continue
    }
}

fn get_upstream_address() -> Option<String> {
    let bytes = get_property(vec!["upstream", "address"]).ok()??;
    String::from_utf8(bytes).ok()
}

fn get_upstream_port() -> Option<u16> {
    let bytes = get_property(vec!["upstream", "port"]).ok()??;
    //TODO: should we handle bytes length other than 2?
    if bytes.len() == 2 {
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    } else {
        None
    }
}

fn get_downstream_remote_address() -> Option<String> {
    let bytes = get_property(vec!["source", "address"]).ok()??;
    String::from_utf8(bytes).ok()
}

fn get_downstream_remote_port() -> Option<u16> {
    let bytes = get_property(vec!["source", "port"]).ok()??;
    if bytes.len() == 2 {
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    } else {
        None
    }
}
