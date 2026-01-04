use api::{
    Aggregatable, ClusterTraffic, HttpGatewayTraffic, HttpMeta, L4Meta, NodePortTraffic, Traffic,
};
use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::Mutex,
};

use crate::label::{ClusterLabel, HttpGatewayLabel, Label, NodePortLabel};

pub const COUNTER_SHARDS: usize = 64;

pub struct CounterTable<K, C> {
    pub shards: Vec<Mutex<HashMap<K, C>>>,
}

impl<K, C> CounterTable<K, C>
where
    K: Hash + Eq,
    C: Aggregatable + Default + Clone,
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
        let entry = guard.entry(key).or_insert(traffic.clone());
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
    C: Aggregatable + Default + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

pub trait TrafficAggregate<L, T>: Send + Sync {
    fn aggregate(&self, label: L, traffic: T);
}

pub trait TrafficDump: Send + Sync {
    fn dump(&self) -> Vec<(Label, Traffic)>;
}

#[derive(Default)]
pub struct TrafficCounter {
    nodeport_traffic_table: CounterTable<NodePortLabel, NodePortTraffic>,
    http_gateway_traffic_table: CounterTable<HttpGatewayLabel, HttpGatewayTraffic>,
    cluster_traffic_table: CounterTable<ClusterLabel, ClusterTraffic>,
}

impl TrafficAggregate<NodePortLabel, NodePortTraffic> for TrafficCounter {
    fn aggregate(&self, label: NodePortLabel, traffic: NodePortTraffic) {
        self.nodeport_traffic_table.aggregate(label, traffic);
    }
}

impl TrafficAggregate<HttpGatewayLabel, HttpGatewayTraffic> for TrafficCounter {
    fn aggregate(&self, label: HttpGatewayLabel, traffic: HttpGatewayTraffic) {
        self.http_gateway_traffic_table.aggregate(label, traffic);
    }
}

impl TrafficAggregate<ClusterLabel, ClusterTraffic> for TrafficCounter {
    fn aggregate(&self, label: ClusterLabel, traffic: ClusterTraffic) {
        self.cluster_traffic_table.aggregate(label, traffic);
    }
}

impl TrafficDump for TrafficCounter {
    fn dump(&self) -> Vec<(Label, Traffic)> {
        let mut results: Vec<(Label, Traffic)> = Vec::new();

        for shard in &self.nodeport_traffic_table.shards {
            let mut guard = shard.lock().expect("CounterTable shard mutex poisoned");
            for (key, value) in guard.drain() {
                results.push((Label::NodePort(key), Traffic::NodePort(value)));
                // results.push(Traffic::NodePort(value));
            }
        }

        for shard in &self.http_gateway_traffic_table.shards {
            let mut guard = shard.lock().expect("CounterTable shard mutex poisoned");
            for (key, value) in guard.drain() {
                results.push((Label::HttpGateway(key), Traffic::HttpGateway((value))));
                // results.push(Traffic::HttpGateway(value));
            }
        }

        for shard in &self.cluster_traffic_table.shards {
            let mut guard = shard.lock().expect("CounterTable shard mutex poisoned");
            for (key, value) in guard.drain() {
                results.push((Label::Cluster(key), Traffic::Cluster(value)));
                // results.push(Traffic::Cluster(value));
            }
        }

        results
    }
}
