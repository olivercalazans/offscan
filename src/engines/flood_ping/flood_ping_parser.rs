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



    /// IP and MAC addresses for Reflection Attack
    #[arg(
        short = 'R',
        long,
        long_help = long_help!(
            "Host with this IP and MAC will send replies to target\n\
            \tExample: 192.168.1.1/11:22:33:aa:bb:cc\n\
            !!! NOTE: It's necessary to infome both IP and MAC\n\
            !!! NOTE: Ignored if --smurf flag is used"
        ),
    )]
    pub reflector: Option<String>,

    

    /// Source IP address (spoofing)
    #[arg(
        long,
        long_help = long_help!("!!! NOTE: Ignored if --smurf or --mirror-ip are used"),
    )]
    pub src_ip: Option<Ipv4Addr>,

    

    /// Source MAC address (spoofing). Use 'local' to use the iface MAC
    #[arg(
        long,
        long_help = long_help!("!!! NOTE: Ignored if --smurf or --mirror-ip are used"),
    )]
    pub src_mac: Option<String>,

}