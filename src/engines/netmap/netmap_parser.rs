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


    /// Set a initial IP
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