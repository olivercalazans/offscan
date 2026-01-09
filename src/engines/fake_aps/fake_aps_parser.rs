use clap::Parser;



#[derive(Parser)]
#[command(name = "fake", about = "Fake AP beacons")]
pub struct FakeApsArgs {

    /// SSID/Network name
    #[arg(short, long, max_length = 32)]
    pub ssid: String,


    /// Interface to be used
    #[arg(short, long)]
    pub iface: String,


    /// Channel
    #[arg(short, long)]
    pub channel: Option<i32>,

}