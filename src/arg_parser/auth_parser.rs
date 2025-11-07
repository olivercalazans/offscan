use clap::Parser;
use crate::arg_parser::parse_mac;



#[derive(Parser)]
#[command(name = "auth", about = "Authentication flooder")]
pub struct AuthArgs {

    /// SSID (Wifi name)
    pub ssid: String,


    /// Define the BSSID
    ///
    /// BSSID is the unique MAC address of a Wi-Fi access point.
    #[arg(long, value_parser = parse_mac)]
    pub bssid: Option<[u8; 6]>,

}