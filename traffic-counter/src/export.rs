use crate::counter::L4CounterTable;
use chrono::Utc;

/// Trait representing anything that can export itself into another form.
pub trait Export {
    /// The result type returned by the export operation.
    type Output;

    /// Perform the export and return the resulting value.
    fn export(&self, table: &L4CounterTable) -> Self::Output;
}

#[derive(Debug, Default, Copy, Clone)]
pub struct LogExporter;

impl Export for LogExporter {
    type Output = ();

    fn export(&self, table: &L4CounterTable) -> Self::Output {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        for shard in &table.shards {
            let mut guard = shard.lock().expect("counter shard mutex poisoned");
            for (flow, counter) in guard.iter() {
                println!("[{timestamp}] flow {} - counter {}", flow, counter);
            }
            guard.clear();
        }
    }
}
