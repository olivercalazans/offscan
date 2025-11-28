use std::net::Ipv4Addr;
use clap::Parser;


#[derive(Parser)]
#[command(name = "banner", about = "Banner Grabber")]
pub struct BannerArgs {

    /// Targe IP
    pub target_ip: Ipv4Addr,

}