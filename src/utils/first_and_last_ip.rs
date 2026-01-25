use std::net::Ipv4Addr;
use crate::generators::Ipv4Iter;



pub(crate) fn get_first_and_last_ip(cidr: &str) -> (u32, u32) {
    let mut ip_range = Ipv4Iter::new(cidr, None);
    let first_ip     = ip_range.next().expect("No IPs in range");
    let last_ip      = Ipv4Addr::from(u32::from(first_ip) + ip_range.total() as u32 - 3);
    (first_ip.into(), last_ip.into())
}