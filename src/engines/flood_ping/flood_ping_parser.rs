use std::net::Ipv4Addr;
use clap::Parser;



#[derive(Parser)]
#[command(name = "ping", about = "Ping Flooder")]
pub struct PingArgs {

    /// Destination IP address to flood
    #[arg(long = "dip")]
    pub dst_ip: Ipv4Addr,


    /// Destination MAC address. "local" = iface MAC, "gateway" = gateway MAC
    #[arg(long = "dmac")]
    pub dst_mac: String,

    
    /// Source IP address. Default: Random
    #[arg(long = "sip")]
    pub src_ip: Option<Ipv4Addr>,
    

    /// Source MAC address. Default: Random, "local" = iface MAC, "gateway" = gateway MAC
    #[arg(long = "smac")]
    pub src_mac: Option<String>,

}