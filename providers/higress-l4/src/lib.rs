use proxy_wasm::{
    hostcalls::register_shared_queue,
    traits::{Context, RootContext, StreamContext},
    types::{ContextType, LogLevel},
};

use crate::log::Log;
mod log;
mod stream;

const QUEUE_NAME: &str = "higress_l4_queue";
const PLUGIN_NAME: &str = "higress_l4_traffic_provider";
struct Provider {
    log: Log,
    queue_id: Option<u32>,
}

impl Default for Provider {
    fn default() -> Self {
        Provider {
            log: Log::new(PLUGIN_NAME.to_string()),
            queue_id: None,
        }
    }
}

// RootContext instances are associated with the plugin as a whole.
// Accordingly, they receive callbacks corresponding to different events in the lifecycle of a plugin
impl RootContext for Provider {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        //TODO: implement me
        match register_shared_queue(QUEUE_NAME) {
            Ok(id) => {
                self.queue_id = Some(id);
            }
            Err(e) => {
                self.log
                    .error(&format!("Failed to register shared queue: {:?}", e));
                return false;
            }
        }
        true
    }
    fn create_stream_context(&self, _context_id: u32) -> Option<Box<dyn StreamContext>> {
        Some(Box::new(stream::StreamHandler::default()))
    }
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::StreamContext)
    }
}

// Context instances are associated with individual streams or connections.
impl Context for Provider {}

proxy_wasm::main! {{
    // Set the log level for the Wasm module. Currently, this is set to LogLevel::Trace for maximum verbosity.
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_context_id| -> Box<dyn RootContext> {
        Box::new(Provider::default())
    });
}}
