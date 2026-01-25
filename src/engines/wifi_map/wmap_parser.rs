use clap::Parser;
use crate::iface::Iface;



#[derive(Parser)]
#[command(name = "wmap", about = "Packet Flooder")]
pub struct WmapArgs {

    /// Interface to be use to get the beacons
    #[arg(short, long)]
    pub iface: Iface,


    /// Sniff beacons from the interface on monitor mode
    #[arg(short = 'M', long)]
    pub monitor: bool,

}