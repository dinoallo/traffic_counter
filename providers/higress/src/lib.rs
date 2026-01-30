use higress_wasm_rust::log::Log;
use ipnet::IpNet;
use prefix_trie::PrefixMap;
use proxy_wasm::hostcalls::{dequeue_shared_queue, register_shared_queue};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use crate::http::HTTPTrafficCounter;
use crate::parse::parse_cidr_from_str;

mod attr;
mod http;
mod parse;

const PLUGIN_NAME: &str = "traffic-counter";
const QUEUE_NAME: &str = "traffic_counter_queue";

fn upstream_counter_name_default() -> String {
    "outbound|50051||traffic_counter.default.svc.cluster.local".to_string()
}

#[derive(Default, Debug, Deserialize, Clone)]
#[serde(default)]
pub struct TrafficCounterConfig {
    pub track_req: bool,
    pub track_resp: bool,
    pub white_list: Vec<String>,
    #[serde(default = "upstream_counter_name_default")]
    pub upstream_counter_name: String,
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
                self.log
                    .infof(format_args!("Registered shared queue with id: {}", id));
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
        let mut http_traffic_counter = HTTPTrafficCounter::default();
        http_traffic_counter.root_config = self.root_config.clone();
        http_traffic_counter.white_list_v4 = self.white_list_v4.clone();
        http_traffic_counter.white_list_v6 = self.white_list_v6.clone();
        http_traffic_counter.queue_id = self.queue_id;
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
                    self.log.debug("Opened gRPC stream");
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
