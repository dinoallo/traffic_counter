use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::Mutex,
};

use crate::counter::TrafficCount;

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

impl<K, C> Default for CounterTable<K, C>
where
    K: Hash + Eq + Copy,
    C: TrafficCount<C> + Default + Copy,
{
    fn default() -> Self {
        Self::new()
    }
}
