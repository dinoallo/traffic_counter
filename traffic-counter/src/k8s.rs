use crate::traffic::{HttpMeta, L4Meta, PodMeta, SvcMeta};
use anyhow::Result;

pub trait K8sInquire {
    fn inquire_ingress(&self, _http_meta: &HttpMeta) -> Result<Option<SvcMeta>> {
        Ok(None)
    }
    fn inquire_nodeport(&self, _l4_meta: &L4Meta) -> Result<Option<SvcMeta>> {
        Ok(None)
    }
    fn inquire_pod_to_world(&self, _l4_meta: &L4Meta) -> Result<Option<PodMeta>> {
        Ok(None)
    }
}
