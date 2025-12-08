use std::net::Ipv4Addr;
use clap::Parser;



#[derive(Parser)]
#[command(name = "udp", about = "UDP Flooder")]
pub struct UdpArgs {

    /// Target IP address to flood
    pub target_ip: Ipv4Addr,


    /// Use "gateway" if the target isn't in the local net
    pub target_mac: String,

}