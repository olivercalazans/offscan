use clap::Parser;
use crate::iface::IfaceInfo;



macro_rules! long_help {
    ($text:expr) => {
        concat!("\n", $text)
    };
}



#[derive(Parser)]
#[command(name = "netmap", about = "Network Mapper")]
pub struct NetMapArgs {

    /// Add a delay between packet transmissions.
    #[arg(
        short, long,
        value_name = "SECONDS",
        default_value = "0.03",
        long_help = long_help!(
            "Add a delay between packet transmissions.\n\
             Examples:\n\
             \t0.5 => fixed delay of 0.5 seconds\n\
             \t1-2 => random delay between 1 and 2 seconds"
        ),
    )]
    pub delay: String,



    /// Define a network interface to send packets
    #[arg(
        short, long,
        value_name = "INTERFACE",
        value_parser = IfaceInfo::check_iface_exists,
        default_value_t = IfaceInfo::default_iface(),
        long_help = long_help!(
            "Define a network interface to send the packets.\n\
            If not specified, defaults to the system's default interface."
        ),
    )]
    pub iface: String,



    /// Set an IP range to scan
    #[arg(
        short, long,
        value_name = "RANGE",
        long_help = long_help!(
            "Set an IP range to scan.\n\n\
            Accepted formats:\n\
            # For local network ranges:\n\
            \t*<ip>     => from first network IP to specified IP\n\
                  \t\t     Example: *192.168.1.100\n\n\
            \t<ip>*     => from specified IP to last network IP\n\
                  \t\t     Example: 192.168.1.100*\n\n\
            \t<ip>*<ip> => all IPs between two addresses\n\
                  \t\t     Example: 192.168.1.1*192.168.1.50\n\n\
            # For external IP ranges:\n\
            \t<ip>*<ip> => all IPs between two addresses\n\
                  \t\t     Example: 8.8.8.1*8.8.8.10"
        ),
    )]
    pub range: Option<String>,


    
    /// Use only ICMP probes
    #[arg(long)]
    pub icmp: bool,


    /// Use only TCP probes
    #[arg(long)]
    pub tcp: bool,

    
    /// Use only UDP probes
    #[arg(long)]
    pub udp: bool,

}