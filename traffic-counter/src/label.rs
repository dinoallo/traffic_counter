use crate::traffic::{
    K8sIngressTraffic, K8sNodePortTraffic, K8sPodToWorldTraffic, K8sTraffic, Traffic,
};
use anyhow::Result;
use std::sync::Arc;
pub trait TrafficLabel<T> {
    fn label(&self, traffic: T) -> Result<T> {
        Ok(traffic)
    }
}

impl TrafficLabel<K8sIngressTraffic> for K8sTrafficLabeler {
    fn label(&self, traffic: K8sIngressTraffic) -> Result<K8sIngressTraffic> {
        // Implement your labeling logic here
        let result = self.k8s_inquirer.inquire_ingress(&traffic.http_meta)?;
        let Some(svc_meta) = result else {
            return Ok(traffic);
        };
        let labeled_traffic = K8sIngressTraffic {
            http_meta: traffic.http_meta,
            svc_meta,
            request_bytes: traffic.request_bytes,
            response_bytes: traffic.response_bytes,
        };
        Ok(labeled_traffic)
    }
}

impl TrafficLabel<K8sNodePortTraffic> for K8sTrafficLabeler {
    fn label(&self, traffic: K8sNodePortTraffic) -> Result<K8sNodePortTraffic> {
        // Implement your labeling logic here
        Ok(traffic)
    }
}

impl TrafficLabel<K8sPodToWorldTraffic> for K8sTrafficLabeler {
    fn label(&self, traffic: K8sPodToWorldTraffic) -> Result<K8sPodToWorldTraffic> {
        // Implement your labeling logic here
        Ok(traffic)
    }
}

impl TrafficLabel<K8sTraffic> for K8sTrafficLabeler {
    fn label(&self, traffic: K8sTraffic) -> Result<K8sTraffic> {
        match traffic {
            K8sTraffic::K8sIngress(t) => {
                let labeled = self.label(t)?;
                Ok(K8sTraffic::K8sIngress(labeled))
            }
            K8sTraffic::K8sNodePort(t) => {
                let labeled = self.label(t)?;
                Ok(K8sTraffic::K8sNodePort(labeled))
            }
            K8sTraffic::K8sPodToWorld(t) => {
                let labeled = self.label(t)?;
                Ok(K8sTraffic::K8sPodToWorld(labeled))
            }
        }
    }
}
pub struct K8sTrafficLabeler {
    // Add any necessary fields here
    k8s_inquirer: Arc<dyn crate::k8s::K8sInquire + Send + Sync>,
}

pub struct TrafficLabeler {
    pub k8s_labeler: K8sTrafficLabeler,
}

impl TrafficLabel<Traffic> for TrafficLabeler {
    fn label(&self, traffic: Traffic) -> Result<Traffic> {
        match traffic {
            Traffic::K8s(t) => {
                let labeled = self.k8s_labeler.label(t)?;
                Ok(Traffic::K8s(labeled))
            }
            Traffic::Unknown => Ok(traffic),
        }
    }
}
