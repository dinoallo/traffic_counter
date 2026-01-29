use api::HttpGatewayTraffic;
use api::proto::trafficcounter::v1::IngestTrafficRequest;
use higress_wasm_rust::log::Log;
use higress_wasm_rust::plugin_wrapper::HttpContextWrapper;
use ipnet::IpNet;
use prefix_trie::PrefixMap;
use prost::Message;
use proxy_wasm::{
    hostcalls::enqueue_shared_queue,
    traits::{Context, HttpContext},
    types::{DataAction, HeaderAction},
};
use serde::Deserialize;
use std::rc::Rc;
use std::sync::Arc;

use crate::{
    PLUGIN_NAME, TrafficCounterConfig,
    attr::{
        get_destination_address, get_destination_port, get_host, get_source_address,
        get_source_port,
    },
    parse::parse_sockaddr_from_str,
};
#[derive(Default, Debug, Deserialize, Clone)]
#[serde(default)]
pub struct HTTPTrafficCounterConfig {}
pub struct HTTPTrafficCounter {
    // These variables are shared across all HTTP contexts
    pub root_config: Arc<TrafficCounterConfig>,
    pub white_list_v4: Arc<PrefixMap<ipnet::Ipv4Net, ()>>,
    pub white_list_v6: Arc<PrefixMap<ipnet::Ipv6Net, ()>>,
    pub queue_id: Option<u32>,
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
            self.log
                .warn("Queue ID not available, dropping traffic data");
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
                self.log.info("Queued traffic request");
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
        if self.track {
            self.log
                .infof(format_args!("IP {} is not in white list, tracking", ip));
        } else {
            self.log
                .infof(format_args!("IP {} is in white list, not tracking", ip));
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
        if _end_of_stream {
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
        if _end_of_stream {
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
        if _end_of_stream {
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
        if _end_of_stream {
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
