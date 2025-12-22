use higress_wasm_rust::log::Log;
use higress_wasm_rust::plugin_wrapper::{HttpContextWrapper, RootContextWrapper};
use higress_wasm_rust::rule_matcher::{RuleMatcher, SharedRuleMatcher, on_configure};
use multimap::MultiMap;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::ops::DerefMut;
use std::rc::Rc;

const PLUGIN_NAME: &str = "traffic-counter";

#[derive(Default, Debug, Deserialize, Clone)]
#[serde(default)]
pub struct HTTPTrafficCounterConfig {}
pub struct HTTPTrafficCounter {
    log: Log,
    config: Option<Rc<HTTPTrafficCounterConfig>>,
    total_response_header_size: usize,
    total_response_body_size: usize,
}

impl Default for HTTPTrafficCounter {
    fn default() -> Self {
        Self {
            log: Log::new(PLUGIN_NAME.to_string()),
            config: None,
            total_response_header_size: 0,
            total_response_body_size: 0,
        }
    }
}

impl Context for HTTPTrafficCounter {}
impl HttpContext for HTTPTrafficCounter {}
impl HttpContextWrapper<HTTPTrafficCounterConfig> for HTTPTrafficCounter {
    fn on_config(&mut self, _config: Rc<HTTPTrafficCounterConfig>) {
        self.config = Some(_config.clone());
    }
    fn on_http_response_complete_headers(
        &mut self,
        _headers: &MultiMap<String, String>,
    ) -> HeaderAction {
        let mut size = 0;
        for (name, value) in _headers {
            size += name.len() + value.len() + 4; // account for ": " and "\r\n"
        }
        self.total_response_header_size += size;
        self.log.debugf(format_args!(
            "total response headers size: {}",
            self.total_response_header_size
        ));
        //TODO: send total response header size to the counter service / redis
        HeaderAction::Continue
    }
    fn on_http_response_complete_body(&mut self, _res_body: &Bytes) -> DataAction {
        self.total_response_body_size += _res_body.len();
        self.log.debugf(format_args!(
            "total response body size: {}",
            self.total_response_body_size
        ));
        //TODO: send total response body size to the counter service / redis
        DataAction::Continue
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
