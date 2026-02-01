use std::net::Ipv4Addr;
use clap::Parser;



#[derive(Parser)]
#[command(name = "tcp", about = "TCP Flooder")]
pub struct TcpArgs {

    /// Target IP address to flood
    #[arg(long = "dip")]
    pub dst_ip: Ipv4Addr,


    /// Use "local" = iface MAC, "gateway" = gateway MAC
    #[arg(long = "dmac")]
    pub dst_mac: String,


    /// Target port
    #[arg(short, long)]
    pub port: u16,


    /// Optional source IP address
    #[arg(long = "sip")]
    pub src_ip: Option<Ipv4Addr>,


    /// Use "local" = iface MAC or "gateway" = gateway MAC
    #[arg(long = "smac")]
    pub src_mac: Option<String>,

}