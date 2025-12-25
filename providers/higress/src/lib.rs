use higress_wasm_rust::log::Log;
use higress_wasm_rust::plugin_wrapper::{HttpContextWrapper, RootContextWrapper};
use higress_wasm_rust::rule_matcher::{RuleMatcher, SharedRuleMatcher, on_configure};
use ipnet::IpNet;
use prefix_trie::PrefixMap;
use proxy_wasm::hostcalls::get_property;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::DerefMut;
use std::rc::Rc;

const PLUGIN_NAME: &str = "traffic-counter";

fn debug_default() -> bool {
    false
}
#[derive(Default, Debug, Deserialize, Clone)]
#[serde(default)]
pub struct HTTPTrafficCounterConfig {
    #[serde(default = "debug_default")]
    pub debug: bool,
    pub white_list: Vec<String>,
}
pub struct HTTPTrafficCounter {
    log: Log,
    config: Rc<HTTPTrafficCounterConfig>,
    track: bool,
    white_list_v4: PrefixMap<ipnet::Ipv4Net, ()>,
    white_list_v6: PrefixMap<ipnet::Ipv6Net, ()>,
    total_response_header_size: usize,
    total_response_body_size: usize,
}

impl Default for HTTPTrafficCounter {
    fn default() -> Self {
        Self {
            log: Log::new(PLUGIN_NAME.to_string()),
            config: Rc::new(HTTPTrafficCounterConfig::default()),
            track: false,
            white_list_v4: PrefixMap::new(),
            white_list_v6: PrefixMap::new(),
            total_response_header_size: 0,
            total_response_body_size: 0,
        }
    }
}

impl HTTPTrafficCounter {
    fn log_final_size(&self) {
        self.log.infof(format_args!(
            "Final total response headers size: {}",
            self.total_response_header_size
        ));
        self.log.infof(format_args!(
            "Final total response body size: {}",
            self.total_response_body_size
        ));
    }
    fn is_white_listed(&self, ip: &IpNet) -> bool {
        match ip {
            IpNet::V4(v4_net) => self.white_list_v4.get_lpm(v4_net).is_some(),
            IpNet::V6(v6_net) => self.white_list_v6.get_lpm(v6_net).is_some(),
        }
    }
}
fn parse_ip_from_str(raw: &str) -> Option<IpNet> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return None;
    }

    if trimmed.contains('.') {
        // Handle IPv4, possibly with port
        let segment = trimmed.split(':').next()?;
        let addr: Ipv4Addr = segment.parse().ok()?;
        let net = ipnet::Ipv4Net::new(addr, 32).ok()?;
        return Some(IpNet::V4(net));
    }

    if trimmed.starts_with('[') {
        // Handle IPv6 with port
        let closing = trimmed.find(']')?;
        if closing <= 1 {
            return None;
        }
        let segment = &trimmed[1..closing];
        let addr: Ipv6Addr = segment.parse().ok()?;
        let net = ipnet::Ipv6Net::new(addr, 128).ok()?;
        return Some(IpNet::V6(net));
    }

    trimmed
        .parse::<Ipv6Addr>()
        .ok()
        .and_then(|addr| ipnet::Ipv6Net::new(addr, 128).ok())
        .map(IpNet::V6)
}

fn parse_ip(bytes: Bytes) -> Option<IpNet> {
    let source = String::from_utf8(bytes.to_vec()).ok()?;
    parse_ip_from_str(&source)
}

pub fn parse_ipnet(net: &str) -> Option<IpNet> {
    parse_ip_from_str(net)
}

impl Context for HTTPTrafficCounter {}
impl HttpContext for HTTPTrafficCounter {
    fn on_http_request_headers(
        &mut self,
        _num_headers: usize,
        _end_of_stream: bool,
    ) -> HeaderAction {
        let bytes = match get_property(vec!["source", "address"]) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                self.log.error("source.address not found");
                return HeaderAction::Continue;
            }
            Err(e) => {
                self.log.errorf(format_args!(
                    "Error getting source address property: {:?}",
                    e
                ));
                return HeaderAction::Continue;
            }
        };

        let ip = match parse_ip(bytes) {
            Some(ip) => ip,
            None => {
                self.log.error("Failed to parse source IP address");
                return HeaderAction::Continue;
            }
        };

        self.track = !self.is_white_listed(&ip);
        if self.config.debug {
            let (verb, action) = if self.track {
                ("not in", "tracking")
            } else {
                ("in", "not tracking")
            };
            self.log
                .infof(format_args!("IP {} is {} white list, {}", ip, verb, action));
        }
        HeaderAction::Continue
    }
    fn on_http_response_headers(
        &mut self,
        _num_headers: usize,
        _end_of_stream: bool,
    ) -> HeaderAction {
        let headers = self.get_http_response_headers();
        let mut size = 0;
        for (name, value) in headers {
            // Adding name, value, and the ": " + CRLF (approx 4 bytes per line)
            size += name.len() + value.len() + 4;
        }
        self.total_response_header_size += size;
        if _end_of_stream && self.config.debug {
            self.log_final_size();
        }
        HeaderAction::Continue
    }
    fn on_http_response_body(&mut self, _body_size: usize, _end_of_stream: bool) -> DataAction {
        self.total_response_body_size += _body_size;
        if _end_of_stream && self.config.debug {
            self.log_final_size();
        }
        DataAction::Continue
    }
}
impl HttpContextWrapper<HTTPTrafficCounterConfig> for HTTPTrafficCounter {
    fn on_config(&mut self, _config: Rc<HTTPTrafficCounterConfig>) {
        self.config = _config.clone();

        let mut white_list_v4 = PrefixMap::new();
        let mut white_list_v6 = PrefixMap::new();

        for entry in &self.config.white_list {
            match parse_ipnet(entry) {
                Some(IpNet::V4(net)) => {
                    white_list_v4.insert(net, ());
                }
                Some(IpNet::V6(net)) => {
                    white_list_v6.insert(net, ());
                }
                None => {
                    self.log.errorf(format_args!(
                        "Invalid CIDR entry in white_list: {} Not loading this entry.",
                        entry
                    ));
                }
            }
        }

        self.white_list_v4 = white_list_v4;
        self.white_list_v6 = white_list_v6;
    }
}

struct TrafficCounter {
    log: Log,
    rule_matcher: SharedRuleMatcher<HTTPTrafficCounterConfig>,
}

impl TrafficCounter {
    fn new() -> Self {
        Self {
            log: Log::new(PLUGIN_NAME.to_string()),
            rule_matcher: Rc::new(RefCell::new(RuleMatcher::default())),
        }
    }
}

impl Context for TrafficCounter {}

impl RootContext for TrafficCounter {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        on_configure(
            self,
            _plugin_configuration_size,
            self.rule_matcher.borrow_mut().deref_mut(),
            &self.log,
        )
    }
    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        self.create_http_context_use_wrapper(context_id)
    }
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

impl RootContextWrapper<HTTPTrafficCounterConfig> for TrafficCounter {
    fn rule_matcher(&self) -> &SharedRuleMatcher<HTTPTrafficCounterConfig> {
        &self.rule_matcher
    }
    fn create_http_context_wrapper(
        &self,
        _context_id: u32,
    ) -> Option<Box<dyn HttpContextWrapper<HTTPTrafficCounterConfig>>> {
        Some(Box::new(HTTPTrafficCounter::default()))
    }
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_context_id| -> Box<dyn RootContext> {
        Box::new(TrafficCounter::new())
    });
}}
