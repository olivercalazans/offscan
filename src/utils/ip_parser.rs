use std::net::Ipv4Addr;
use crate::utils::abort;



pub fn parse_ip(ip_str: &str) -> Ipv4Addr {
    let ip: Ipv4Addr = ip_str.parse().unwrap_or_else(|e| {
        abort(&format!("Invalid IP '{}': {}", ip_str, e));
    });

    ip
}