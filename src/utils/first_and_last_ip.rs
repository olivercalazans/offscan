use std::net::Ipv4Addr;
use crate::generators::Ipv4Iter;
use crate::iface::IfaceInfo;
use crate::utils::abort;



pub fn get_first_and_last_ip(iface: &str) -> (u32, u32) {
    let cidr         = IfaceInfo::iface_cidr(iface).unwrap_or_else(|e| abort(e));
    let mut ip_range = Ipv4Iter::new(&cidr, None);
    let first_ip     = ip_range.next().expect("No IPs in range");
    let last_ip      = Ipv4Addr::from(u32::from(first_ip) + ip_range.total() as u32 - 3);
    (first_ip.into(), last_ip.into())
}