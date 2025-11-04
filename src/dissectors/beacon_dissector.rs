#[derive(Debug, Clone)]
pub struct BeaconInfo {
    pub bssid:   String,
    pub ssid:    String,
    pub channel: u8,
}



pub fn parse_beacon_packet(packet_data: &[u8]) -> Option<BeaconInfo> {
    if packet_data.len() < 24 {
        return None;
    }

    let frame_control = u16::from_le_bytes([packet_data[0], packet_data[1]]);
    let frame_type    = (frame_control >> 2) & 0x03; 
    let frame_subtype = (frame_control >> 4) & 0x0F;

    if frame_type != 0 || frame_subtype != 8 {
        return None;
    }

    let bssid   = get_bssid(packet_data);
    let ssid    = get_ssid(packet_data);
    let channel = get_channel(packet_data);

    Some(BeaconInfo {
        bssid,
        ssid,
        channel,
    })
}



pub fn get_bssid(packet_data: &[u8]) -> String {
    if packet_data.len() < 22 {
        return "00:00:00:00:00:00".to_string();
    }

    let bssid_bytes = &packet_data[16..22];
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
        bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]
    )
}



pub fn get_ssid(packet_data: &[u8]) -> String {
    if packet_data.len() < 38 {
        return "<hidden>".to_string();
    }

    let mut offset = 36;

    while offset + 1 < packet_data.len() {
        let element_id     = packet_data[offset];
        let element_length = packet_data[offset + 1] as usize;

        if element_id == 0 && element_length > 0 {
            let ssid_start = offset + 2;
            let ssid_end   = ssid_start + element_length;

            if ssid_end <= packet_data.len() {
                let ssid_bytes = &packet_data[ssid_start..ssid_end];
                
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
        
        if offset >= packet_data.len() {
            break;
        }
    }

    "<hidden>".to_string()
}



pub fn get_channel(packet_data: &[u8]) -> u8 {
    if packet_data.len() < 38 {
        return 0;
    }

    let mut offset = 36;

    while offset + 1 < packet_data.len() {
        let element_id     = packet_data[offset];
        let element_length = packet_data[offset + 1] as usize;

        if element_id == 3 && element_length == 1 {
            let channel_start = offset + 2;
            if channel_start < packet_data.len() {
                return packet_data[channel_start];
            }
        }

        offset += 2 + element_length;
        
        if offset >= packet_data.len() {
            break;
        }
    }

    0
}



pub fn get_signal_strength(packet_data: &[u8]) -> Option<i8> {
    if packet_data.len() > 10 {
        for i in 0..packet_data.len().saturating_sub(1) {
            if packet_data[i] > 128 {
                return Some((packet_data[i] as i8).saturating_abs() * -1);
            }
        }
    }
    
    None
}