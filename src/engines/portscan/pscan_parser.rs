use std::net::Ipv4Addr;
use clap::Parser;


#[derive(Parser)]
#[command(name = "pscan", about = "Port scanner")]
pub struct PortScanArgs {

    /// Target IP
    pub target_ip: Ipv4Addr,


    /// Scan specific ports or ranges of ports (can be combined).
    ///
    /// Examples: Specific: 22,80 | Range: 20-50 | Combined: 22,50-100
    #[arg(short, long, default_value = "0-100")]
    pub ports: String,


    /// Scan the ports in random order
    #[arg(short, long)]
    pub random: bool,


    /// Add a delay between packet transmissions.
    ///
    /// Examples: 0.5 or 1-2 (seconds).
    #[arg(short, long, default_value = "0.03")]
    pub delay: String,

    
    /// Scan UDP ports
    #[arg(short = 'U', long = "UDP")]
    pub udp: bool,

}