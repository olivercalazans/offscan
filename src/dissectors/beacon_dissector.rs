pub struct BeaconDissector;



impl BeaconDissector {

    pub fn parse_beacon(packet: &[u8]) -> Option<Vec<String>> {
        if packet.len() < 24 {
            return None;
        }

        let frame_control = u16::from_le_bytes([packet[0], packet[1]]);
        let frame_type    = (frame_control >> 2) & 0x03; 
        let frame_subtype = (frame_control >> 4) & 0x0F;

        if frame_type != 0 || frame_subtype != 8 {
            return None;
        }

        let bssid   = Self::get_bssid(packet);
        let ssid    = Self::get_ssid(packet);
        let channel = Self::get_channel(packet);

        vec![bssid, ssid, channel.to_string()].into()
    }



    fn get_bssid(packet: &[u8]) -> String {
        if packet.len() < 22 {
            return "00:00:00:00:00:00".to_string();
        }

        let bssid_bytes = &packet[16..22];
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
            bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]
        )
    }



    fn get_ssid(packet: &[u8]) -> String {
        if packet.len() < 38 {
            return "<hidden>".to_string();
        }

        let mut offset = 36;

        while offset + 1 < packet.len() {
            let element_id     = packet[offset];
            let element_length = packet[offset + 1] as usize;

            if element_id == 0 && element_length > 0 {
                let ssid_start = offset + 2;
                let ssid_end   = ssid_start + element_length;

                if ssid_end <= packet.len() {
                    let ssid_bytes = &packet[ssid_start..ssid_end];

                    if ssid_bytes.iter().all(|&b| b == 0) {
                        return "<hidden>".to_string();
                    }

                    match String::from_utf8(ssid_bytes.to_vec()) {
                        Ok(ssid) if !ssid.trim().is_empty() => return ssid,
                        _ => {
                            return format!("{:02X?}", ssid_bytes);
                        }
                    }
                }
            }

            offset += 2 + element_length;

            if offset >= packet.len() {
                break;
            }
        }

        "<hidden>".to_string()
    }



    fn get_channel(packet: &[u8]) -> u8 {
        if packet.len() < 38 {
            return 0;
        }

        let mut offset = 36;

        while offset + 1 < packet.len() {
            let element_id     = packet[offset];
            let element_length = packet[offset + 1] as usize;

            if element_id == 3 && element_length == 1 {
                let channel_start = offset + 2;
                if channel_start < packet.len() {
                    return packet[channel_start];
                }
            }

            offset += 2 + element_length;

            if offset >= packet.len() {
                break;
            }
        }

        0
    }

}