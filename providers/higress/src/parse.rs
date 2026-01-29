use ipnet::IpNet;

pub fn parse_sockaddr_from_str(raw: &str) -> Option<(IpNet, u16)> {
    let addr: std::net::SocketAddr = raw.parse().ok()?;
    Some((ipnet::IpNet::from(addr.ip()), addr.port()))
}

pub fn parse_cidr_from_str(raw: &str) -> Option<IpNet> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return None;
    }
    let ip_net: IpNet = trimmed.parse().ok()?;
    Some(ip_net)
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_ipv4_cidr() {
        let expected = IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 24).unwrap());
        assert_eq!(parse_cidr_from_str("10.1.2.3/24"), Some(expected));
    }

    #[test]
    fn parses_ipv4_with_port_segment() {
        let expected_ip = IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 32).unwrap());
        let expected_port = 443;
        assert_eq!(
            parse_sockaddr_from_str("10.1.2.3:443"),
            Some((expected_ip, expected_port))
        );
    }

    #[test]
    fn parses_ipv6_cidr() {
        let expected = IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5), 64).unwrap(),
        );
        assert_eq!(parse_cidr_from_str("2001:db8::5/64"), Some(expected));
    }

    #[test]
    fn parses_ipv6_with_port_segment() {
        let expected = IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5), 128).unwrap(),
        );
        assert_eq!(
            parse_sockaddr_from_str("[2001:db8::5]:8080").map(|(ip, _)| ip),
            Some(expected)
        );
    }

    #[test]
    fn parses_ipv6_cidr_trims_and_accepts_ipv6() {
        let expected = IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 8), 64).unwrap(),
        );
        assert_eq!(parse_cidr_from_str(" 2001:db8::8/64 "), Some(expected));
    }

    #[test]
    fn parse_cidr_rejects_empty_input() {
        assert!(parse_cidr_from_str("   ").is_none());
    }
}
