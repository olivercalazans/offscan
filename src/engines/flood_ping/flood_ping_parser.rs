use std::net::Ipv4Addr;
use clap::Parser;



#[derive(Parser)]
#[command(name = "ping", about = "Ping Flooder")]
pub struct PingArgs {

    /// Destination IP address to flood
    pub dst_ip: Ipv4Addr,


    /// Destination MAC address. Use 'local' to use the iface MAC
    pub dst_mac: String,

    
    /// Source IP address. Default: Random
    #[arg(long)]
    pub src_ip: Option<Ipv4Addr>,
    

    /// Source MAC address. Default: Random. Use 'local' to use the iface MAC
    #[arg(long)]
    pub src_mac: Option<String>,

}