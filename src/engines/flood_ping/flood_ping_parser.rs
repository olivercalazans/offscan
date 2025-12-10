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


    /// Target MAC address. Use 'local' to use the iface MAC
    pub target_mac: String,


    /// Use Smurf attack (sends ping broadcasts)
    #[arg(short = 'S', long)]
    pub smurf: bool,

    
    /// Source IP address (spoofing).
    #[arg(
        long,
        long_help = long_help!("!!! NOTE: Ignored if --smurf is used"),
    )]
    pub src_ip: Option<Ipv4Addr>,
    

    /// Source MAC address (spoofing). Use 'local' to use the iface MAC
    #[arg(
        long,
        long_help = long_help!("!!! NOTE: Ignored if --smurf is used"),
    )]
    pub src_mac: Option<String>,

}