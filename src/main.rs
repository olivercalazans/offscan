pub mod arg_parser;
pub mod dissectors;
pub mod engines;
pub mod generators;
pub mod iface;
pub mod pkt_builder;
pub mod sniffer;
pub mod sockets;
pub mod utils;


use std::{env, mem};
use clap::Parser;
use crate::arg_parser::*;
use crate::engines::*;
use crate::utils::abort;



fn main() {
    let mut offscan = Command::new();
    offscan.run();
}



#[derive(Default)]
struct Command {
    arguments: Vec<String>,
    command:   String,
}


impl Command {

    pub fn new() -> Self {
        Default::default()
    }



    pub fn run(&mut self) {
        self.validate_input();
        self.execute_function();
    }



    fn validate_input(&mut self) {
        let input: Vec<String> = env::args().skip(1).collect();
        
        if input.is_empty() {
            abort("No input found");
        }

        self.command   = input[0].clone();
        self.arguments = input;
    }



    fn execute_function(&mut self) {
        match self.command.as_str() {
            "-h"     => Self::display_commands(),
            "--help" => Self::display_commands(),
            "auth"   => self.execute_auth_flood(),
            "banner" => self.execute_banner_grab(),
            "flood"  => self.execute_flood(),
            "info"   => self.execute_info(),
            "netmap" => self.execute_netmap(),
            "ping"   => self.execute_ping(),
            "pscan"  => self.execute_pscan(),
            "protun" => self.execute_protun(),
            "wmap"   => self.execute_wmap(),
            _        => abort(format!("No command '{}'", self.command)),
        }
    }


    
    fn display_commands() {
        println!("\nAvailable commands:");
        println!("\tauth   -> 802.11 Auth Flooding");
        println!("\tbanner -> Banner Grabbing");
        println!("\tflood  -> Packet Flooding");
        println!("\tinfo   -> Network Information");
        println!("\tnetmap -> Network Mapping");
        println!("\tping   -> Ping Flooding");
        println!("\tpscan  -> Port Scanning");
        println!("\tprotun -> Protocol Tunneling");
        println!("\twmap   -> Wifi Mapping");
        println!("");
    }



    fn get_arguments(&mut self) -> Vec<String> {
        mem::take(&mut self.arguments)
    }



    fn execute_auth_flood(&mut self) {
        let cmd_args = AuthArgs::parse_from(self.get_arguments());
        let mut auth = AuthenticationFlooder::new(cmd_args);
        auth.execute();
    }



    fn execute_banner_grab(&mut self) {
        let cmd_args   = BannerArgs::parse_from(self.get_arguments());
        let mut banner = BannerGrabber::new(cmd_args);
        banner.execute();
    }



    fn execute_ping(&mut self) {
        let cmd_args = PingArgs::parse_from(self.get_arguments());
        let mut ping = PingFlooder::new(cmd_args);
        ping.execute();
    }


    
    fn execute_flood(&mut self) {
        let cmd_args  = FloodArgs::parse_from(self.get_arguments());
        let mut flood = PacketFlooder::new(cmd_args);
        flood.execute();
    }



    fn execute_info(&mut self) {
        NetInfoArgs::parse_from(self.get_arguments());
        NetworkInfo::execute();
    }


    
    fn execute_netmap(&mut self) {
        let cmd_args   = NetMapArgs::parse_from(self.get_arguments());
        let mut mapper = NetworkMapper::new(cmd_args);
        mapper.execute();
    }


    
    fn execute_pscan(&mut self) {
        let cmd_args    = PortScanArgs::parse_from(self.get_arguments());
        let mut scanner = PortScanner::new(cmd_args);
        scanner.execute();
    }


    
    fn execute_protun(&mut self) {
        let cmd_args   = TunnelArgs::parse_from(self.get_arguments());
        let mut tunnel = ProtocolTunneler::new(cmd_args);
        tunnel.execute();
    }

    

    fn execute_wmap(&mut self) {
        let cmd_args = WmapArgs::parse_from(self.get_arguments());
        let mut wmap = WifiMapper::new(cmd_args);
        wmap.execute();
    }

}