use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::Mutex,
};

use crate::traffic::{
    Aggregatable, HttpMeta, K8sIngressTraffic, K8sNodePortTraffic, K8sPodToWorldTraffic, L4Meta,
    L4Traffic, Traffic,
};

pub const COUNTER_SHARDS: usize = 64;

pub struct CounterTable<K, C> {
    pub shards: Vec<Mutex<HashMap<K, C>>>,
}

impl<K, C> CounterTable<K, C>
where
    K: Hash + Eq,
    C: Aggregatable + Default,
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

    pub fn aggregate(&self, key: K, traffic: C) {
        let idx = self.shard_index(&key);
        let mut guard = self.shards[idx]
            .lock()
            .expect("CounterTable shard mutex poisoned");
        let entry = guard.entry(key).or_insert(C::default());
        entry.aggregate(&traffic);
    }
    pub fn clear(&self, key: K) -> Option<C> {
        let idx = self.shard_index(&key);
        let mut guard = self.shards[idx]
            .lock()
            .expect("CounterTable shard mutex poisoned");
        guard.remove(&key)
    }
}

impl<K, C> Default for CounterTable<K, C>
where
    K: Hash + Eq,
    C: Aggregatable + Default,
{
    fn default() -> Self {
        Self::new()
    }
}

pub trait TrafficCount: Send + Sync {
    fn aggregate(&self, traffic: Traffic);
    fn reset(&self) -> Vec<Traffic>;
}

#[derive(Default)]
pub struct TrafficCounter {
    k8s_ingress_table: CounterTable<HttpMeta, K8sIngressTraffic>,
    k8s_nodeport_table: CounterTable<L4Meta, K8sNodePortTraffic>,
    k8s_pod_to_world_table: CounterTable<L4Meta, K8sPodToWorldTraffic>,
    l4_table: CounterTable<L4Meta, L4Traffic>,
}

impl TrafficCount for TrafficCounter {
    fn aggregate(&self, traffic: Traffic) {
        match traffic {
            Traffic::K8sIngress(ingress) => {
                self.k8s_ingress_table
                    .aggregate(ingress.http_meta.clone(), ingress);
            }
            Traffic::K8sNodePort(nodeport) => {
                self.k8s_nodeport_table
                    .aggregate(nodeport.l4_meta.clone(), nodeport);
            }
            Traffic::K8sPodToWorld(pod_to_world) => {
                self.k8s_pod_to_world_table
                    .aggregate(pod_to_world.l4_meta.clone(), pod_to_world);
            }
            Traffic::L4(l4) => {
                self.l4_table.aggregate(l4.l4_meta.clone(), l4);
            }
            _ => {}
        }
    }
    fn reset(&self) -> Vec<Traffic> {
        let mut results = Vec::new();

        for shard in &self.k8s_ingress_table.shards {
            let mut guard = shard.lock().expect("CounterTable shard mutex poisoned");
            for (_, value) in guard.drain() {
                results.push(Traffic::K8sIngress(value));
            }
        }

        for shard in &self.k8s_nodeport_table.shards {
            let mut guard = shard.lock().expect("CounterTable shard mutex poisoned");
            for (_, value) in guard.drain() {
                results.push(Traffic::K8sNodePort(value));
            }
        }

        for shard in &self.k8s_pod_to_world_table.shards {
            let mut guard = shard.lock().expect("CounterTable shard mutex poisoned");
            for (_, value) in guard.drain() {
                results.push(Traffic::K8sPodToWorld(value));
            }
        }

        for shard in &self.l4_table.shards {
            let mut guard = shard.lock().expect("CounterTable shard mutex poisoned");
            for (_, value) in guard.drain() {
                results.push(Traffic::L4(value));
            }
        }

        results
    }
}
