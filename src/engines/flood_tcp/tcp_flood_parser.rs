use std::net::Ipv4Addr;
use clap::Parser;



#[derive(Parser)]
#[command(name = "tcp", about = "TCP Flooder")]
pub struct TcpArgs {

    /// Target IP address to flood
    pub target_ip: Ipv4Addr,


    /// Use "gateway" if the target isn't in the intranet
    pub target_mac: String,


    /// Target port
    pub port: u16,


    /// Optional source IP address
    pub src_ip: Option<Ipv4Addr>,


    /// Use "local" to use the interface MAC address
    pub src_mac: Option<String>,


    /// Use ACK packets
    #[arg(long)]
    pub ack: bool,

}