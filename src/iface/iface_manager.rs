use std::process::{Command, Stdio};



pub struct InterfaceManager;


impl InterfaceManager {

    pub fn set_channel(iface: &str, channel: u32) -> bool {
        let output = Command::new("sudo")
            .args(&["iw", "dev", iface, "set", "channel", &channel.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if output.is_err() {
            return false;
        }

        true
    }

}