use std::net::Ipv4Addr;
use clap::Parser;



#[derive(Parser)]
#[command(name = "dns", about = "DNS Flooder")]
pub struct DnsArgs {

    /// Target IP address to flood
    pub target_ip: Ipv4Addr,


    /// DNS server to amplificate the packet lengths
    pub dns_ip: Ipv4Addr,

}