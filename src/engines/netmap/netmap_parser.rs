use clap::Parser;
use crate::iface::IfaceInfo;


#[derive(Parser)]
#[command(name = "netmap", about = "Network Mapper")]
pub struct NetMapArgs {

    /// Add a delay between packet transmissions.
    ///
    /// Examples: 0.5 or 1-2 (seconds).
    #[arg(short, long, default_value = "0.03")]
    pub delay: String,


    /// Define a network interface to send the packets
    #[arg(
        short, long,
        value_parser = IfaceInfo::check_iface_exists,
        default_value_t = IfaceInfo::default_iface_name()
    )]
    pub iface: String,


    /// Set an IP range
    ///
    /// Accepted formats:
    /// For local network ranges:
    /// - "<ip>" - from first network IP to specified IP (e.g., "192.168.1.100")
    /// - "<ip>*" - from specified IP to last network IP (e.g., "192.168.1.100*")
    /// - "<ip>*<ip>" - all IPs between two addresses (e.g., "192.168.1.1*192.168.1.50")
    ///
    /// For external IP ranges:
    /// - "<ip>*<ip>" - all IPs between two addresses (e.g., "8.8.8.1*8.8.8.10")
    #[arg(short, long)]
    pub range: Option<String>,



    /// Use only ICMP probes
    #[arg(long)]
    pub icmp: bool,


    /// Use only TCP probes
    #[arg(long)]
    pub tcp: bool,


    /// Use only TCP probes
    #[arg(long)]
    pub udp: bool,

}