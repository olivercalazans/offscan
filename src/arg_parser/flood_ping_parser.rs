use std::net::Ipv4Addr;
use clap::Parser;



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
    ///
    /// Host with this IP will send replies to target
    /// NOTE: Ignored if --smurf flag is used
    #[arg(long)]
    pub reflector_ip: Option<Ipv4Addr>,


    /// MAC address for Reflection Attack
    ///
    /// Host with this MAC will send replies to target
    /// Use "local" for interface's MAC address
    /// NOTE: Requires --mirror-ip to be effective
    #[arg(long)]
    pub reflector_mac: Option<String>,

    
    /// Source IP address (spoofing)
    ///
    /// NOTE: Ignored if --smurf or --mirror-ip are used
    #[arg(long)]
    pub src_ip: Option<Ipv4Addr>,

    
    /// Source MAC address (spoofing)
    ///
    /// NOTE: Ignored if --smurf or --mirror-ip are used
    #[arg(long)]
    pub src_mac: Option<String>,

}