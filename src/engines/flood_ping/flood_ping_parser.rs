use std::net::Ipv4Addr;
use clap::Parser;



macro_rules! long_help {
    ($text:expr) => {
        concat!("\n", $text)
    };
}



#[derive(Parser)]
#[command(name = "ping", about = "Ping Flooder")]
pub struct PingArgs {

    /// Target IP address to flood
    pub target_ip: Ipv4Addr,


    /// Target MAC address
    pub target_mac: String,


    /// Use Smurf attack (sends ping broadcasts)
    #[arg(short = 'S', long)]
    pub smurf: bool,


    /// IP address for Reflection Attack
    #[arg(
        long,
        long_help = long_help!(
            "Host with this IP will send replies to target\n\
            NOTE: Ignored if --smurf flag is used"
        ),
    )]
    pub reflector_ip: Option<Ipv4Addr>,


    /// MAC address for Reflection Attack
    #[arg(
        long,
        long_help = long_help!(
            "Host with this MAC will send replies to target\n\
            Use 'local' for interface's MAC address\n\
            NOTE: Requires --mirror-ip to be effective"
        ),
    )]
    pub reflector_mac: Option<String>,

    
    /// Source IP address (spoofing)
    #[arg(
        long,
        long_help = long_help!("NOTE: Ignored if --smurf or --mirror-ip are used"),
    )]
    pub src_ip: Option<Ipv4Addr>,

    
    /// Source MAC address (spoofing)
    #[arg(
        long,
        long_help = long_help!("NOTE: Ignored if --smurf or --mirror-ip are used"),
    )]
    pub src_mac: Option<String>,

}