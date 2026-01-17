use clap::Parser;
use crate::iface::IfaceInfo;
use crate::utils::TypeConverter;


#[derive(Parser)]
#[command(name = "deauth", about = "Deauthentication attack")]
pub struct DeauthArgs {

    /// Define a network interface to send the frames
    #[arg(short, long, value_parser = IfaceInfo::exists)]
    pub iface: String,


    /// Target MAC
    #[arg(short, long, value_parser = TypeConverter::mac_str_to_vec_u8)]
    pub target_mac: [u8; 6],


    /// BSSID
    #[arg(short, long, value_parser = TypeConverter::mac_str_to_vec_u8)]
    pub bssid: [u8; 6],


    /// Delay between frame sendings (milliseconds)
    #[arg(short, long, default_value_t = 30)]
    pub delay: u64,


    /// Channel
    #[arg(short, long)]
    pub channel: i32,

}