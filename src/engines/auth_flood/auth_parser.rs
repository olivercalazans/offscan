use clap::Parser;
use crate::iface::IfaceInfo;
use crate::utils::parse_mac;



macro_rules! long_help {
    ($text:expr) => {
        concat!("\n", $text)
    };
}



#[derive(Parser)]
#[command(name = "auth", about = "802.11 Authentication flooder")]
pub struct AuthArgs {

    /// Interface to be use to send the frames
    #[arg(value_parser = IfaceInfo::check_iface_exists)]
    pub iface: String,


    /// SSID (Wifi name)
    pub ssid: String,


    /// Define the BSSID
    #[arg(
        long, 
        value_parser = parse_mac,
        long_help = long_help!("BSSID is the unique MAC address of a Wi-Fi access point."),
    )]
    pub bssid: Option<[u8; 6]>,

}