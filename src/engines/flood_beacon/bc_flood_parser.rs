use clap::Parser;
use crate::iface::IfaceInfo;
use crate::utils::parse_channel;



#[derive(Parser)]
#[command(name = "fake", about = "Fake AP beacons")]
pub struct BcFloodArgs {

    /// SSID/Network name
    #[arg(short, long, value_parser = parse_ssid)]
    pub ssid: String,


    /// Interface to be used
    #[arg(short, long, value_parser = IfaceInfo::exists)]
    pub iface: String,


    /// Channel
    #[arg(short, long, value_parser = parse_channel)]
    pub channel: i32,

}



fn parse_ssid(ssid: &str) -> Result<String, String> {
    let bytes = ssid.as_bytes();

    if bytes.len() > 32 {
        return Err(format!("The SSID has more than 32 characters"));
    }

    Ok(ssid.to_string())
}