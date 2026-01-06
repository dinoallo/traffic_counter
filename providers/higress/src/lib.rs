use api::HttpGatewayTraffic;
use higress_wasm_rust::log::Log;
use higress_wasm_rust::plugin_wrapper::HttpContextWrapper;
use ipnet::IpNet;
use prefix_trie::PrefixMap;
use proxy_wasm::hostcalls::{
    dequeue_shared_queue, enqueue_shared_queue, get_property, register_shared_queue,
};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;

use api::proto::trafficcounter::v1::IngestTrafficRequest;

const PLUGIN_NAME: &str = "traffic-counter";
const QUEUE_NAME: &str = "traffic_counter_queue";

fn debug_default() -> bool {
    false
}

fn upstream_counter_name_default() -> String {
    "outbound|50051||traffic_counter.default.svc.cluster.local".to_string()
}
#[derive(Default, Debug, Deserialize, Clone)]
#[serde(default)]
pub struct HTTPTrafficCounterConfig {}
pub struct HTTPTrafficCounter {
    // These variables are shared across all HTTP contexts
    root_config: Arc<TrafficCounterConfig>,
    white_list_v4: Arc<PrefixMap<ipnet::Ipv4Net, ()>>,
    white_list_v6: Arc<PrefixMap<ipnet::Ipv6Net, ()>>,
    queue_id: Option<u32>,
    // These variables are local to each HTTP context
    log: Log,
    config: Rc<HTTPTrafficCounterConfig>,
    track: bool,
    total_request_header_size: usize,
    total_request_body_size: usize,
    total_response_header_size: usize,
    total_response_body_size: usize,
    // Downstream connection remote address
    source_address: String,
    // Downstream connection remote port
    source_port: u16,
    // Downstream connection local address
    destination_address: String,
    // Downstream connection local port
    destination_port: u16,
    // The host portion of the URL
    host: String,
}

impl Default for HTTPTrafficCounter {
    fn default() -> Self {
        Self {
            log: Log::new(PLUGIN_NAME.to_string()),
            root_config: Arc::new(TrafficCounterConfig::default()),
            config: Rc::new(HTTPTrafficCounterConfig::default()),
            track: false,
            white_list_v4: Arc::new(PrefixMap::new()),
            white_list_v6: Arc::new(PrefixMap::new()),
            queue_id: None,
            total_request_header_size: 0,
            total_request_body_size: 0,
            total_response_header_size: 0,
            total_response_body_size: 0,
            source_address: String::new(),
            source_port: 0,
            destination_address: String::new(),
            destination_port: 0,
            host: String::new(),
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
    fn send_traffic(&self) {
        let Some(queue_id) = self.queue_id else {
            if self.root_config.debug {
                self.log
                    .warn("Queue ID not available, dropping traffic data");
            }
            return;
        };

        let http_meta = api::HttpMeta {
            host_ip: self.destination_address.clone(),
            client_ip: self.source_address.clone(),
            host: self.host.clone(),
        };
        let traffic = api::Traffic::HttpGateway(HttpGatewayTraffic {
            http_meta,
            request_bytes: self.total_request_header_size as u64
                + self.total_request_body_size as u64,
            response_bytes: self.total_response_header_size as u64
                + self.total_response_body_size as u64,
        });
        let request = IngestTrafficRequest {
            traffic: Some(traffic.into()),
        };

        let mut buf = Vec::new();
        if let Err(e) = request.encode(&mut buf) {
            self.log
                .errorf(format_args!("Failed to encode traffic request: {}", e));
            return;
        }

        match enqueue_shared_queue(queue_id, Some(buf.as_slice())) {
            Ok(_) => {
                if self.root_config.debug {
                    self.log.info("Queued traffic request");
                }
            }
            Err(e) => {
                self.log
                    .errorf(format_args!("Failed to enqueue traffic request: {:?}", e));
            }
        }
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
        let source_address = match get_source_address() {
            Some(addr) => addr,
            None => {
                self.log.error("source.address not found or invalid");
                return HeaderAction::Continue;
            }
        };
        self.source_address = source_address.clone();
        let source_port = match get_source_port() {
            Some(port) => port,
            None => {
                self.log.error("source.port not found or invalid");
                return HeaderAction::Continue;
            }
        };
        self.source_port = source_port;
        let destination_address = match get_destination_address() {
            Some(addr) => addr,
            None => {
                self.log.error("destination.address not found or invalid");
                return HeaderAction::Continue;
            }
        };
        self.destination_address = destination_address.clone();
        let destination_port = match get_destination_port() {
            Some(port) => port,
            None => {
                self.log.error("destination.port not found or invalid");
                return HeaderAction::Continue;
            }
        };
        self.destination_port = destination_port;
        let host = match get_host() {
            Some(h) => h,
            None => {
                self.log.error("request.host not found or invalid");
                return HeaderAction::Continue;
            }
        };
        self.host = host;
        let ip = match parse_sockaddr_from_str(&source_address) {
            Some((ip, _)) => ip,
            None => {
                self.log.error("Failed to parse source IP address");
                return HeaderAction::Continue;
            }
        };

        self.track = !self.is_white_listed(&ip);
        if self.root_config.debug {
            let (verb, action) = if self.track {
                ("not in", "tracking")
            } else {
                ("in", "not tracking")
            };
            self.log
                .infof(format_args!("IP {} is {} white list, {}", ip, verb, action));
        }
        // if not tracking, skip further processing
        if !self.track || !self.root_config.track_req {
            return HeaderAction::Continue;
        }
        let headers = self.get_http_request_headers();
        let mut size = 0;
        for (name, value) in headers {
            // Adding name, value, and the ": " + CRLF (approx 4 bytes per line)
            size += name.len() + value.len() + 4;
        }
        self.total_request_header_size += size;
        if _end_of_stream && self.root_config.debug {
            self.log_final_size();
            self.send_traffic();
        }
        HeaderAction::Continue
    }
    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> DataAction {
        if !self.track || !self.root_config.track_req {
            return DataAction::Continue;
        }
        self.total_request_body_size += _body_size;
        if _end_of_stream && self.root_config.debug {
            self.log_final_size();
            self.send_traffic();
        }
        DataAction::Continue
    }
    fn on_http_response_headers(
        &mut self,
        _num_headers: usize,
        _end_of_stream: bool,
    ) -> HeaderAction {
        if !self.track || !self.root_config.track_resp {
            return HeaderAction::Continue;
        }
        let headers = self.get_http_response_headers();
        let mut size = 0;
        for (name, value) in headers {
            // Adding name, value, and the ": " + CRLF (approx 4 bytes per line)
            size += name.len() + value.len() + 4;
        }
        self.total_response_header_size += size;
        if _end_of_stream && self.root_config.debug {
            self.log_final_size();
            self.send_traffic();
        }
        HeaderAction::Continue
    }
    fn on_http_response_body(&mut self, _body_size: usize, _end_of_stream: bool) -> DataAction {
        if !self.track || !self.root_config.track_resp {
            return DataAction::Continue;
        }
        self.total_response_body_size += _body_size;
        if _end_of_stream && self.root_config.debug {
            self.log_final_size();
            self.send_traffic();
        }
        DataAction::Continue
    }
}
impl HttpContextWrapper<HTTPTrafficCounterConfig> for HTTPTrafficCounter {
    fn on_config(&mut self, _config: Rc<HTTPTrafficCounterConfig>) {
        self.config = _config.clone();
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct TrafficCounterConfig {
    #[serde(default = "debug_default")]
    pub debug: bool,
    pub track_req: bool,
    pub track_resp: bool,
    pub white_list: Vec<String>,
    #[serde(default = "upstream_counter_name_default")]
    pub upstream_counter_name: String,
}

impl Default for TrafficCounterConfig {
    fn default() -> Self {
        Self {
            debug: debug_default(),
            track_req: false,
            track_resp: false,
            white_list: Vec::new(),
            upstream_counter_name: String::new(),
        }
    }
}

struct TrafficCounter {
    log: Log,
    root_config: Arc<TrafficCounterConfig>,
    white_list_v4: Arc<PrefixMap<ipnet::Ipv4Net, ()>>,
    white_list_v6: Arc<PrefixMap<ipnet::Ipv6Net, ()>>,
    queue_id: Option<u32>,
    stream_token: Option<u32>,
}

impl Default for TrafficCounter {
    fn default() -> Self {
        Self {
            log: Log::new(PLUGIN_NAME.to_string()),
            root_config: Arc::new(TrafficCounterConfig::default()),
            white_list_v4: Arc::new(PrefixMap::new()),
            white_list_v6: Arc::new(PrefixMap::new()),
            queue_id: None,
            stream_token: None,
        }
    }
}

impl Context for TrafficCounter {
    fn on_grpc_stream_close(&mut self, token_id: u32, status_code: u32) {
        if self.stream_token == Some(token_id) {
            self.log.warnf(format_args!(
                "gRPC stream closed with status: {}",
                status_code
            ));
            self.stream_token = None;
        }
    }
    fn on_grpc_call_response(&mut self, token_id: u32, status_code: u32, _response_size: usize) {
        if status_code != 0 {
            self.log.warnf(format_args!(
                "gRPC call response received with non-zero status: {}",
                status_code
            ));
            if self.stream_token == Some(token_id) {
                self.stream_token = None;
            }
        }
    }
}

impl RootContext for TrafficCounter {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        let config_buffer = self.get_plugin_configuration().unwrap_or_default();
        let config =
            if let Ok(config) = serde_json::from_slice::<TrafficCounterConfig>(&config_buffer) {
                config
            } else {
                self.log
                    .error("Using default configuration due to parse error.");
                TrafficCounterConfig::default()
            };
        self.root_config = Arc::new(config);
        let mut white_list_v4 = PrefixMap::new();
        let mut white_list_v6 = PrefixMap::new();

        for entry in &self.root_config.white_list {
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
        self.white_list_v4 = Arc::new(white_list_v4);
        self.white_list_v6 = Arc::new(white_list_v6);

        match register_shared_queue(QUEUE_NAME) {
            Ok(id) => {
                self.queue_id = Some(id);
                if self.root_config.debug {
                    self.log
                        .infof(format_args!("Registered shared queue with id: {}", id));
                }
            }
            Err(e) => {
                self.log
                    .errorf(format_args!("Failed to register shared queue: {:?}", e));
            }
        }

        self.set_tick_period(Duration::from_millis(100));
        true
    }
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        let http_traffic_counter = HTTPTrafficCounter {
            log: Log::new(PLUGIN_NAME.to_string()),
            root_config: self.root_config.clone(),
            white_list_v4: self.white_list_v4.clone(),
            white_list_v6: self.white_list_v6.clone(),
            queue_id: self.queue_id,
            ..Default::default()
        };
        Some(Box::new(http_traffic_counter))
    }
    fn on_tick(&mut self) {
        let Some(queue_id) = self.queue_id else {
            return;
        };

        if self.stream_token.is_none() {
            // The stream_token being None indicates that we don't currently have an open gRPC stream to the traffic counter service, so we attempt to open one.
            if self.root_config.upstream_counter_name.is_empty() {
                return;
            }
            match self.open_grpc_stream(
                &self.root_config.upstream_counter_name,
                "trafficcounter.v1.TrafficIngestor",
                "IngestTraffic",
                vec![],
            ) {
                Ok(token) => {
                    self.stream_token = Some(token);
                    if self.root_config.debug {
                        self.log.info("Opened gRPC stream");
                    }
                }
                Err(e) => {
                    self.log
                        .errorf(format_args!("Failed to open gRPC stream: {:?}", e));
                }
            }
        }

        loop {
            match dequeue_shared_queue(queue_id) {
                Ok(Some(data)) => {
                    if self.stream_token.is_some() {
                        // At this point we have a valid stream token and queue ID, so we can attempt to send any queued traffic data
                        // unwrap is safe because we check for None above
                        self.send_grpc_stream_message(
                            self.stream_token.unwrap(),
                            Some(&data),
                            false,
                        )
                    }
                    // If self.stream_token is somehow still None, we do nothing (by discarding the data) to prevent filling up the shared queue.
                }
                Ok(None) => break, // Queue is empty
                Err(e) => {
                    self.log
                        .errorf(format_args!("Failed to dequeue from shared queue: {:?}", e));
                    break;
                }
            }
        }
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_context_id| -> Box<dyn RootContext> {
        Box::new(TrafficCounter::default())
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

fn get_source_address() -> Option<String> {
    let bytes = get_property(vec!["source", "address"]).ok()??;
    String::from_utf8(bytes.to_vec()).ok()
}

fn get_destination_address() -> Option<String> {
    let bytes = get_property(vec!["destination", "address"]).ok()??;
    String::from_utf8(bytes.to_vec()).ok()
}

fn get_source_port() -> Option<u16> {
    let bytes = get_property(vec!["source", "port"]).ok()??;
    if bytes.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn get_destination_port() -> Option<u16> {
    let bytes = get_property(vec!["destination", "port"]).ok()??;
    if bytes.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn get_host() -> Option<String> {
    let bytes = get_property(vec!["request", "host"]).ok()??;
    String::from_utf8(bytes.to_vec()).ok()
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
