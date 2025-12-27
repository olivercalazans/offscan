pub mod dissectors;
pub mod engines;
pub mod generators;
pub mod iface;
pub mod pkt_builder;
pub mod sniffer;
pub mod sockets;
pub mod utils;

use std::{env, mem};
use crate::engines::*;
use crate::utils::abort;



fn main() {
    let mut offscan = Command::new();
    offscan.run();
}


#[derive(Default)]
struct Command {
    arguments : Vec<String>,
    command   : String,
}


impl Command {

    pub fn new() -> Self {
        Self { ..Default::default() }
    }



    pub fn run(&mut self) {
        self.validate_input();
        
        if self.command == "-h" || self.command == "--help" {
            self.display_commands();
            return;
        }

        self.execute_command();
    }



    fn validate_input(&mut self) {
        let input: Vec<String> = env::args().skip(1).collect();
        
        if input.is_empty() {
            abort("No input found");
        }

        self.command = input[0].clone();
        self.arguments = input;
    }

    

    fn display_commands(&self) {
        println!("\nAvailable commands:");
        
        for (name, description, _) in Self::get_command_registry() {
            println!("\t{:<6} -> {}", name, description);
        }
        println!("");
    }

    
    
    fn get_command_registry() -> Vec<(&'static str, &'static str, Box<dyn Fn(Vec<String>)>)> {
        vec![
            ("banner", "Banner Grabbing",         Box::new(execute::<BannerArgs,   BannerGrabber>)),
            ("deauth", "Deauthentication attack", Box::new(execute::<DeauthArgs,   Deauthentication>)),
            ("dns",    "DNS Flooding",            Box::new(execute::<DnsArgs,      DnsFlooder>)),
            ("flood",  "Packet Flooding",         Box::new(execute::<FloodArgs,    PacketFlooder>)),
            ("info",   "Network Information",     Box::new(execute::<NetInfoArgs,  NetworkInfo>)),
            ("netmap", "Network Mapping",         Box::new(execute::<NetMapArgs,   NetworkMapper>)),
            ("ping",   "Ping Flooding",           Box::new(execute::<PingArgs,     PingFlooder>)),
            ("pscan",  "Port Scanning",           Box::new(execute::<PortScanArgs, PortScanner>)),
            ("tcp",    "TCP Flooding",            Box::new(execute::<TcpArgs,      TcpFlooder>)),
            ("wmap",   "Wifi Mapping",            Box::new(execute::<WmapArgs,     WifiMapper>)),
        ]
    }

    
    
    fn execute_command(&mut self) {
        for (name, _, executor) in Self::get_command_registry() {
            if name == self.command {
                executor(mem::take(&mut self.arguments));
                return;
            }
        }
        
        abort(format!("No command '{}'", self.command));
    }
}



fn execute<P, E>(args: Vec<String>)
where
    P: clap::Parser,
    E: EngineTrait<Args = P>,
{
    let cmd_args = P::parse_from(args);
    let mut cmd  = E::new(cmd_args);
    cmd.execute();
}



pub trait EngineTrait {
    type Args: clap::Parser;
    
    fn new(args: Self::Args) -> Self;
    fn execute(&mut self);
}