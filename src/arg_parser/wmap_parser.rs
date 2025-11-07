use clap::Parser;


#[derive(Parser)]
#[command(name = "wmap", about = "Packet Flooder")]
pub struct WmapArgs {

    /// Set a time to wait before close the beacons capture
    #[arg(short, long, default_value_t = 2)]
    pub time: u64,

}