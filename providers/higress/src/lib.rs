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
    pub track_req: bool,
    pub track_resp: bool,
    pub white_list: Vec<String>,
}
pub struct HTTPTrafficCounter {
    log: Log,
    config: Rc<HTTPTrafficCounterConfig>,
    track: bool,
    white_list_v4: PrefixMap<ipnet::Ipv4Net, ()>,
    white_list_v6: PrefixMap<ipnet::Ipv6Net, ()>,
    total_request_header_size: usize,
    total_request_body_size: usize,
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
            total_request_header_size: 0,
            total_request_body_size: 0,
            total_response_header_size: 0,
            total_response_body_size: 0,
        }
    }
}

impl HTTPTrafficCounter {
    fn log_final_size(&self) {
        self.log.infof(format_args!(
            "Final total request/response headers size: {}/{}",
            self.total_request_header_size, self.total_response_header_size
        ));
        self.log.infof(format_args!(
            "Final total request/response body size: {}/{}",
            self.total_request_body_size, self.total_response_body_size
        ));
    }
    fn is_white_listed(&self, ip: &IpNet) -> bool {
        match ip {
            IpNet::V4(v4_net) => self.white_list_v4.get_lpm(v4_net).is_some(),
            IpNet::V6(v6_net) => self.white_list_v6.get_lpm(v6_net).is_some(),
        }
    }
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

        let source = match String::from_utf8(bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                self.log.error("Failed to convert source address to string");
                return HeaderAction::Continue;
            }
        };
        let ip = match parse_sockaddr_from_str(&source) {
            Some((ip, _)) => ip,
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
        // if not tracking, skip further processing
        if !self.track || !self.config.track_req {
            return HeaderAction::Continue;
        }
        let headers = self.get_http_request_headers();
        let mut size = 0;
        for (name, value) in headers {
            // Adding name, value, and the ": " + CRLF (approx 4 bytes per line)
            size += name.len() + value.len() + 4;
        }
        self.total_request_header_size += size;
        if _end_of_stream && self.config.debug {
            self.log_final_size();
        }
        HeaderAction::Continue
    }
    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> DataAction {
        if !self.track || !self.config.track_req {
            return DataAction::Continue;
        }
        self.total_request_body_size += _body_size;
        if _end_of_stream && self.config.debug {
            self.log_final_size();
        }
        DataAction::Continue
    }
    fn on_http_response_headers(
        &mut self,
        _num_headers: usize,
        _end_of_stream: bool,
    ) -> HeaderAction {
        if !self.track || !self.config.track_resp {
            return HeaderAction::Continue;
        }
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
        if !self.track || !self.config.track_resp {
            return DataAction::Continue;
        }
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
            match parse_cidr_from_str(entry) {
                Some(IpNet::V4(net)) => {
                    self.log
                        .infof(format_args!("Adding IPv4 CIDR to white_list: {}", net));
                    white_list_v4.insert(net, ());
                }
                Some(IpNet::V6(net)) => {
                    self.log
                        .infof(format_args!("Adding IPv6 CIDR to white_list: {}", net));
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

fn parse_sockaddr_from_str(raw: &str) -> Option<(IpNet, u16)> {
    let addr: std::net::SocketAddr = raw.parse().ok()?;
    Some((ipnet::IpNet::from(addr.ip()), addr.port()))
}

fn parse_cidr_from_str(raw: &str) -> Option<IpNet> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return None;
    }
    let ip_net: IpNet = trimmed.parse().ok()?;
    Some(ip_net)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_ipv4_cidr() {
        let expected = IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 24).unwrap());
        assert_eq!(parse_cidr_from_str("10.1.2.3/24"), Some(expected));
    }

    #[test]
    fn parses_ipv4_with_port_segment() {
        let expected_ip = IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 32).unwrap());
        let expected_port = 443;
        assert_eq!(
            parse_sockaddr_from_str("10.1.2.3:443"),
            Some((expected_ip, expected_port))
        );
    }

    #[test]
    fn parses_ipv6_cidr() {
        let expected = IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5), 64).unwrap(),
        );
        assert_eq!(parse_cidr_from_str("2001:db8::5/64"), Some(expected));
    }

    #[test]
    fn parses_ipv6_with_port_segment() {
        let expected = IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5), 128).unwrap(),
        );
        assert_eq!(
            parse_sockaddr_from_str("[2001:db8::5]:8080").map(|(ip, _)| ip),
            Some(expected)
        );
    }

    #[test]
    fn parses_ipv6_cidr_trims_and_accepts_ipv6() {
        let expected = IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 8), 64).unwrap(),
        );
        assert_eq!(parse_cidr_from_str(" 2001:db8::8/64 "), Some(expected));
    }

    #[test]
    fn parse_cidr_rejects_empty_input() {
        assert!(parse_cidr_from_str("   ").is_none());
    }
}
