use clap::Parser;
use crate::iface::IfaceInfo;



#[derive(Parser)]
#[command(name = "wmap", about = "Packet Flooder")]
pub struct WmapArgs {

    /// Interface to be use to get the beacons
    #[arg(short, long, value_parser = IfaceInfo::exists)]
    pub iface: String,


    /// Sniff beacons from the interface on monitor mode
    #[arg(short = 'M', long)]
    pub monitor: bool,

}