use proxy_wasm::hostcalls::get_property;

pub fn get_source_address() -> Option<String> {
    let bytes = get_property(vec!["source", "address"]).ok()??;
    String::from_utf8(bytes.to_vec()).ok()
}

pub fn get_destination_address() -> Option<String> {
    let bytes = get_property(vec!["destination", "address"]).ok()??;
    String::from_utf8(bytes.to_vec()).ok()
}

pub fn get_source_port() -> Option<u16> {
    let bytes = get_property(vec!["source", "port"]).ok()??;
    if bytes.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub fn get_destination_port() -> Option<u16> {
    let bytes = get_property(vec!["destination", "port"]).ok()??;
    if bytes.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub fn get_host() -> Option<String> {
    let bytes = get_property(vec!["request", "host"]).ok()??;
    String::from_utf8(bytes.to_vec()).ok()
}
