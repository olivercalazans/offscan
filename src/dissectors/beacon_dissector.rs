pub struct BeaconDissector;


impl BeaconDissector {

    pub fn parse_beacon(packet: &[u8]) -> Option<Vec<String>> {
        let frame = Self::skip_headers(packet);
        
        if frame.len() < 24 {
            return None;
        }

        let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
        let frame_type    = (frame_control >> 2) & 0x03; 
        let frame_subtype = (frame_control >> 4) & 0x0F;

        if frame_type != 0 || frame_subtype != 8 {
            return None;
        }

        let bssid   = Self::get_bssid(frame);
        let ssid    = Self::get_ssid(frame);
        let channel = Self::get_channel(frame);

        Some(vec![bssid, ssid, channel.to_string()])
    }



    fn skip_headers(packet: &[u8]) -> &[u8] {
        if let Some(offset) = Self::find_frame_start_by_type(packet) {
            return &packet[offset..];
        }

        if let Some(offset) = Self::skip_radiotap_header(packet) {
            return &packet[offset..];
        }

        if let Some(offset) = Self::skip_common_headers(packet) {
            return &packet[offset..];
        }

        packet
    }



    fn find_frame_start_by_type(packet: &[u8]) -> Option<usize> {
        for i in 0..packet.len().saturating_sub(24) {
            if i + 2 > packet.len() {
                continue;
            }

            let frame_control = u16::from_le_bytes([packet[i], packet[i+1]]);
            let frame_type    = (frame_control >> 2) & 0x03;
            let frame_subtype = (frame_control >> 4) & 0x0F;

            if frame_type != 0 || frame_subtype != 8 {
                continue;
            }

            if i + 3 >= packet.len() {
                continue;
            }

            let duration = u16::from_le_bytes([packet[i+2], packet[i+3]]);
            if duration > 0x3AFF {
                continue;
            }

            return Some(i);
        }

        None
    }



    fn skip_radiotap_header(packet: &[u8]) -> Option<usize> {
        if packet.len() < 8 || packet[0] != 0x00 || packet[1] != 0x00 {
            return None
        }

        let radiotap_len = u16::from_le_bytes([packet[2], packet[3]]) as usize;
        if radiotap_len < 8 || radiotap_len + 24 > packet.len() {
            return None;
        }

        let after_radiotap = &packet[radiotap_len..];
        if after_radiotap.len() < 24 {
            return None;
        }

        let frame_control = u16::from_le_bytes([after_radiotap[0], after_radiotap[1]]);
        let frame_type    = (frame_control >> 2) & 0x03;
        if frame_type > 2 {
            return None;
        }

        Some(radiotap_len)
    }



    fn skip_common_headers(packet: &[u8]) -> Option<usize> {
        let common_offsets = [0, 4, 8, 12, 16, 24, 32, 36];

        for &offset in &common_offsets {
            if offset + 24 > packet.len() {
                continue;
            }

            let frame_data    = &packet[offset..];
            let frame_control = u16::from_le_bytes([frame_data[0], frame_data[1]]);
            let frame_type    = (frame_control >> 2) & 0x03;
            let frame_subtype = (frame_control >> 4) & 0x0F;
            
            if frame_type != 0 || frame_subtype != 8 {
                continue;
            }

            return Some(offset);
        }

        None
    }



    fn get_bssid(frame: &[u8]) -> String {
        if frame.len() < 22 {
            return "00:00:00:00:00:00".to_string();
        }

        let bssid_bytes = &frame[16..22];
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
            bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]
        )
    }



    fn get_ssid(frame: &[u8]) -> String {
        if frame.len() < 38 {
            return "<hidden>".to_string();
        }

        let mut offset = 36;

        while offset + 1 < frame.len() {
            let element_id = frame[offset];
            let element_length = frame[offset + 1] as usize;

            if element_id == 0 && element_length > 0 {
                let ssid_start = offset + 2;
                let ssid_end = ssid_start + element_length;

                if ssid_end <= frame.len() {
                    let ssid_bytes = &frame[ssid_start..ssid_end];
                    
                    if ssid_bytes.iter().all(|&b| b == 0) {
                        return "<hidden>".to_string();
                    }
                    
                    match String::from_utf8(ssid_bytes.to_vec()) {
                        Ok(ssid) if !ssid.trim().is_empty() => return ssid,
                        _ => return String::from_utf8_lossy(ssid_bytes).to_string(),
                    }
                }
            }

            offset += 2 + element_length;
            if offset >= frame.len() {
                break;
            }
        }

        "<hidden>".to_string()
    }



    fn get_channel(frame: &[u8]) -> u8 {
        if frame.len() < 38 {
            return 0;
        }

        let mut offset = 36;

        while offset + 1 < frame.len() {
            let element_id = frame[offset];
            let element_length = frame[offset + 1] as usize;

            if element_id == 3 && element_length == 1 {
                let channel_start = offset + 2;
                if channel_start < frame.len() {
                    return frame[channel_start];
                }
            }

            offset += 2 + element_length;
            if offset >= frame.len() {
                break;
            }
        }

        0
    }
    
}