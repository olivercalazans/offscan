use clap::Parser;
use crate::iface::Iface;
use crate::utils::{parse_channel, Mac, Bssid};



#[derive(Parser)]
#[command(name = "deauth", about = "Deauthentication attack")]
pub struct DeauthArgs {

    /// Define a network interface to send the frames
    #[arg(short, long)]
    pub iface: Iface,


    /// Target MAC
    #[arg(short, long, value_parser = Mac::from_str)]
    pub target_mac: Mac,


    /// BSSID
    #[arg(short, long, value_parser = Bssid::from_str)]
    pub bssid: Bssid,


    /// Delay between frame sendings (milliseconds)
    #[arg(short, long, default_value_t = 30)]
    pub delay: u64,


    /// Channel
    #[arg(short, long, value_parser = parse_channel)]
    pub channel: i32,

}