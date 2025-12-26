use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::Mutex,
};

use crate::counter::L4Counter;
use crate::model::Flow;
use crate::traffic::Traffic;

pub const COUNTER_SHARDS: usize = 64;

pub struct CounterTable<K, C> {
    pub shards: Vec<Mutex<HashMap<K, C>>>,
}

impl<K, C> CounterTable<K, C>
where
    K: Hash + Eq + Copy,
    C: TrafficCount<C> + Default + Copy,
{
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(COUNTER_SHARDS);
        for _ in 0..COUNTER_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self { shards }
    }

    pub fn shard_index(&self, key: &K) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len().max(1)
    }

    pub fn increment(&self, key: K, traffic: C) {
        let idx = self.shard_index(&key);
        let mut guard = self.shards[idx]
            .lock()
            .expect("CounterTable shard mutex poisoned");
        let entry = guard.entry(key).or_insert(C::default());
        entry.increment(traffic);
    }
}

pub struct L4CounterTable {
    pub shards: Vec<Mutex<HashMap<Flow, L4Counter>>>,
}

impl L4CounterTable {
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
            .expect("L4Counter shard mutex poisoned");
        let entry = guard.entry(key).or_insert(L4Counter {
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
            .expect("L4Counter shard mutex poisoned");
        let entry = guard.entry(key).or_insert(L4Counter {
            rx_bytes: 0,
            rx_packets: 0,
            tx_bytes: 0,
            tx_packets: 0,
        });
        entry.tx_bytes = entry.tx_bytes.wrapping_add(bytes);
        entry.tx_packets = entry.tx_packets.wrapping_add(packets);
    }
}

impl Default for L4CounterTable {
    fn default() -> Self {
        Self::new()
    }
}
