use clap::Parser;
use crate::iface::IfaceInfo;
use crate::utils::parse_mac;


#[derive(Parser)]
#[command(name = "deauth", about = "Deauthentication attack")]
pub struct DeauthArgs {

    /// Define a network interface to send the frames
    #[arg(short, long, value_parser = IfaceInfo::check_iface_exists)]
    pub iface: String,


    /// Target MAC
    #[arg(short, long, value_parser = parse_mac)]
    pub target_mac: [u8; 6],


    /// AP MAC
    #[arg(short, long, value_parser = parse_mac)]
    pub ap_mac: [u8; 6],


    /// BSSID
    #[arg(short, long, value_parser = parse_mac)]
    pub bssid: [u8; 6],


    /// Delay between frame sendings (milliseconds)
    #[arg(short, long, default_value_t = 200)]
    pub delay: u64,

}