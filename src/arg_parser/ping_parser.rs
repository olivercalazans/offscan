use std::net::Ipv4Addr;
use clap::Parser;
use crate::arg_parser::parse_mac;


#[derive(Parser)]
#[command(name = "ping", about = "Ping Flooder")]
pub struct PingArgs {

    /// Target IP
    pub target_ip: Ipv4Addr,


    /// Define the target MAC
    #[arg(long, value_parser = parse_mac)]
    pub target_mac: Option<[u8; 6]>,


    /// Use the Smurf attack
    ///
    /// This attack send a ping broadcast
    #[arg(short = 'S', long)]
    pub smurf: bool,

}