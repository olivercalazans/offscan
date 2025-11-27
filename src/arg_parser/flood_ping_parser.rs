use std::net::Ipv4Addr;
use clap::Parser;



#[derive(Parser)]
#[command(name = "ping", about = "Ping Flooder")]
pub struct PingArgs {

    /// Target IP
    pub target_ip: Ipv4Addr,


    /// Define the target MAC
    pub target_mac: String,


    /// Use the Smurf attack
    ///
    /// This attack send a ping broadcast
    #[arg(short = 'S', long)]
    pub smurf: bool,


    /// Set an IP to perform a Reflection Attack
    ///
    /// The host with this IP will send the reply packets to the target
    /// WARNING: THIS FLAG WILL BE IGNORED IF THE SMURF FLAG IS USED
    #[arg(long)]
    pub mirror_ip: Option<Ipv4Addr>,


    /// Set a MAC to perform a Reflection Attack
    /// 
    /// The host with this MAC will send the reply packets to the target
    /// Write "local" to use the iface MAC
    /// WARNING: THIS MAC WILL BE USED IF A MIRROR IP IS SET TOO
    #[arg(long)]
    pub mirror_mac: Option<String>,


    // Set a MAC to perform a Reflection Attack
    /// 
    /// The host with this MAC will send the reply packets to the target
    /// WARNING: THIS MAC WILL BE USED IF A MIRROR IP IS SET TOO
    #[arg(long)]
    pub mirror_mac: Option<String>,

}