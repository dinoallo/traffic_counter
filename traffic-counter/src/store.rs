use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::Mutex,
};

use crate::model::{Counter, Flow};

use chrono::Utc;

pub const COUNTER_SHARDS: usize = 64;

pub struct CounterTable {
    shards: Vec<Mutex<HashMap<Flow, Counter>>>,
}

impl CounterTable {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(COUNTER_SHARDS);
        for _ in 0..COUNTER_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self { shards }
    }

    fn shard_index(&self, key: &Flow) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len().max(1)
    }

    #[allow(dead_code)]
    pub fn increment_rx(&self, key: Flow, bytes: u64, packets: u64) {
        let idx = self.shard_index(&key);
        let mut guard = self.shards[idx]
            .lock()
            .expect("counter shard mutex poisoned");
        let entry = guard.entry(key).or_insert(Counter {
            rx_bytes: 0,
            rx_packets: 0,
            tx_bytes: 0,
            tx_packets: 0,
        });
        entry.rx_bytes = entry.rx_bytes.wrapping_add(bytes);
        entry.rx_packets = entry.rx_packets.wrapping_add(packets);
    }

    pub fn increment_tx(&self, key: Flow, bytes: u64, packets: u64) {
        let idx = self.shard_index(&key);
        let mut guard = self.shards[idx]
            .lock()
            .expect("counter shard mutex poisoned");
        let entry = guard.entry(key).or_insert(Counter {
            rx_bytes: 0,
            rx_packets: 0,
            tx_bytes: 0,
            tx_packets: 0,
        });
        entry.tx_bytes = entry.tx_bytes.wrapping_add(bytes);
        entry.tx_packets = entry.tx_packets.wrapping_add(packets);
    }

    /*
    fn snapshot(&self) -> HashMap<IpKey, Counters> {
        let mut merged = HashMap::new();
        for shard in &self.shards {
            let guard = shard.lock().expect("counter shard mutex poisoned");
            for (key, counters) in guard.iter() {
                merged.insert(*key, *counters);
            }
        }
        merged
    }
    */

    fn snapshot_shard(&self, shard_idx: usize) -> HashMap<Flow, Counter> {
        let mut snapshot = HashMap::new();
        if shard_idx < self.shards.len() {
            let mut guard = self.shards[shard_idx]
                .lock()
                .expect("counter shard mutex poisoned");
            for (key, counters) in guard.iter() {
                snapshot.insert(*key, *counters);
            }
            guard.clear();
        }
        snapshot
    }
}

impl Default for CounterTable {
    fn default() -> Self {
        Self::new()
    }
}

pub fn log_snapshot(table: &CounterTable) {
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    /*
    let total_bytes: u64 = table
        .shards
        .iter()
        .map(|shard| {
            let guard = shard.lock().expect("counter shard mutex poisoned");
            guard.values().map(|c| c.bytes).sum::<u64>()
        })
        .sum();
    let total_packets: u64 = table
        .shards
        .iter()
        .map(|shard| {
            let guard = shard.lock().expect("counter shard mutex poisoned");
            guard.values().map(|c| c.packets).sum::<u64>()
        })
        .sum();
    println!("[{timestamp}] Total bytes: {total_bytes} packets: {total_packets}");
    */
    for shard_idx in 0..table.shards.len() {
        let snapshot = table.snapshot_shard(shard_idx);
        for (key, counter) in &snapshot {
            println!("[{timestamp}] flow {} - counter {}", key, counter);
        }
    }
}
