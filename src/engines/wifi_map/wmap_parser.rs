use clap::Parser;
use crate::iface::IfaceInfo;


#[derive(Parser)]
#[command(name = "wmap", about = "Packet Flooder")]
pub struct WmapArgs {

    /// Interface to be use to get the beacons
    #[arg(value_parser = IfaceInfo::check_iface_exists)]
    pub iface: String,

    
    /// Set a time to wait before close the beacons capture
    #[arg(short, long, default_value_t = 2)]
    pub time: u64,

}