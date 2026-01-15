use crate::utils::TypeConverter;


pub(crate) struct BeaconDissector;


impl BeaconDissector {

    pub fn parse_beacon(beacon: &[u8]) -> Option<Vec<String>> {
        let frame = Self::skip_headers(beacon);
        
        if frame.len() < 24 {
            return None;
        }

        let frame_ctrl    = u16::from_le_bytes([frame[0], frame[1]]);
        let frame_type    = (frame_ctrl >> 2) & 0x03; 
        let frame_subtype = (frame_ctrl >> 4) & 0x0F;

        if frame_type != 0 || frame_subtype != 8 {
            return None;
        }

        let bssid = Self::get_bssid(frame);
        let ssid  = Self::get_ssid(frame);
        let chnl  = Self::get_channel(frame);
        let sec   = Self::get_sec_type(frame);

        Some(vec![ssid, bssid, chnl.to_string(), sec])
    }



    fn skip_headers(beacon: &[u8]) -> &[u8] {
        if let Some(offset) = Self::find_frame_start_by_type(beacon) {
            return &beacon[offset..];
        }

        if let Some(offset) = Self::skip_radiotap_header(beacon) {
            return &beacon[offset..];
        }

        if let Some(offset) = Self::skip_common_headers(beacon) {
            return &beacon[offset..];
        }

        beacon
    }



    fn find_frame_start_by_type(beacon: &[u8]) -> Option<usize> {
        for i in 0..beacon.len().saturating_sub(24) {
            if i + 2 > beacon.len() {
                continue;
            }

            let frame_ctrl = u16::from_le_bytes([beacon[i], beacon[i+1]]);
            let frame_type    = (frame_ctrl >> 2) & 0x03;
            let frame_subtype = (frame_ctrl >> 4) & 0x0F;

            if frame_type != 0 || frame_subtype != 8 {
                continue;
            }

            if i + 3 >= beacon.len() {
                continue;
            }

            let duration = u16::from_le_bytes([beacon[i+2], beacon[i+3]]);
            if duration > 0x3AFF {
                continue;
            }

            return Some(i);
        }

        None
    }



    fn skip_radiotap_header(beacon: &[u8]) -> Option<usize> {
        if beacon.len() < 8 || beacon[0] != 0x00 || beacon[1] != 0x00 {
            return None
        }

        let radiotap_len = u16::from_le_bytes([beacon[2], beacon[3]]) as usize;
        if radiotap_len < 8 || radiotap_len + 24 > beacon.len() {
            return None;
        }

        let after_radiotap = &beacon[radiotap_len..];
        if after_radiotap.len() < 24 {
            return None;
        }

        let frame_ctrl = u16::from_le_bytes([after_radiotap[0], after_radiotap[1]]);
        let frame_type = (frame_ctrl >> 2) & 0x03;
        if frame_type > 2 {
            return None;
        }

        Some(radiotap_len)
    }



    fn skip_common_headers(beacon: &[u8]) -> Option<usize> {
        let common_offsets = [0, 4, 8, 12, 16, 24, 32, 36];

        for &offset in &common_offsets {
            if offset + 24 > beacon.len() {
                continue;
            }

            let frame_data    = &beacon[offset..];
            let frame_ctrl    = u16::from_le_bytes([frame_data[0], frame_data[1]]);
            let frame_type    = (frame_ctrl >> 2) & 0x03;
            let frame_subtype = (frame_ctrl >> 4) & 0x0F;
            
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
        TypeConverter::mac_vec_u8_to_string(bssid_bytes)
    }



    fn get_ssid(frame: &[u8]) -> String {
        if frame.len() < 38 {
            return "<hidden>".to_string();
        }

        let mut offset = 36;

        while offset + 1 < frame.len() {
            let element_id     = frame[offset];
            let element_length = frame[offset + 1] as usize;
            offset += 2;

            if element_id != 0 || element_length <= 0 {                
                offset += element_length;
                continue;
            }

            let ssid_start = offset;
            let ssid_end   = ssid_start + element_length;

            if ssid_end > frame.len() {
                offset += element_length;
                continue;
            }

            let ssid_bytes = &frame[ssid_start..ssid_end];
                    
            if ssid_bytes.iter().all(|&b| b == 0) {
                return "<hidden>".to_string();
            }
    
            if let Ok(ssid) = String::from_utf8(ssid_bytes.to_vec()) {
                if !ssid.trim().is_empty() {
                    return ssid;
                }
            }
                    
            return Self::format_ssid_bytes(ssid_bytes);
        }

        "<hidden>".to_string()
    }



    fn format_ssid_bytes(ssid_bytes: &[u8]) -> String {
        let is_printable = ssid_bytes.iter().all(|&b| b >= 32 && b <= 126);
        
        if is_printable {
            return String::from_utf8_lossy(ssid_bytes).to_string();
        }
        
        let display_len      = std::cmp::min(8, ssid_bytes.len());
        let hex_part: String = ssid_bytes[..display_len]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join("");
            
        if ssid_bytes.len() > display_len {
            return format!("{}...", hex_part);
        } 
        
        hex_part
    }



    fn get_channel(frame: &[u8]) -> u8 {
        if frame.len() < 38 {
            return 0;
        }

        let mut offset = 36;

        while offset + 1 < frame.len() {
            let element_id     = frame[offset];
            let element_length = frame[offset + 1] as usize;
            offset += 2;

            if element_id != 3
               || element_length != 1
               || offset >= frame.len()
            {
                offset += element_length;
                continue;
            }

            return frame[offset];
        }

        0
    }



    fn get_sec_type(frame: &[u8]) -> String {
        if frame.len() < 38 {
            return "????".to_string();
        }

        let mut sec_flags = SecFlags::new();
        let mut offset = 36;

        while offset + 1 < frame.len() {
            let element_id = frame[offset];
            let element_length = frame[offset + 1] as usize;

            if offset + 2 + element_length > frame.len() {
                break;
            }

            let element_data = &frame[offset + 2..offset + 2 + element_length];

            match element_id {
                0x30 => Self::process_rsn_element(element_data, &mut sec_flags),
                0xDD => Self::process_vendor_element(element_data, &mut sec_flags),
                0x06 => Self::process_privacy_element(element_data, &mut sec_flags),
                _ => {}
            }

            offset += 2 + element_length;
        }

        sec_flags.to_sec_string()
    }



    fn process_rsn_element(data: &[u8], flags: &mut SecFlags) {
        flags.has_rsn = true;
        flags.is_open = false;

        if data.len() >= 20 {
            flags.is_wpa3 = Self::check_for_wpa3(data);
        }
    }



    fn check_for_wpa3(rsn_data: &[u8]) -> bool {
        let mut offset = 6; // Version (2 bytes) Group Cipher Suite (4 bytes)

        if offset + 2 > rsn_data.len() {
            return false;
        }

        let pairwise_count = u16::from_le_bytes([rsn_data[offset], rsn_data[offset + 1]]) as usize;
        offset += 2 + (pairwise_count * 4);

        if offset + 2 > rsn_data.len() {
            return false;
        }

        let akm_count = u16::from_le_bytes([rsn_data[offset], rsn_data[offset + 1]]) as usize;
        offset += 2;

        for _ in 0..akm_count {
            if offset + 3 >= rsn_data.len() {
                break;
            }

            if rsn_data[offset] != 0x00 ||
               rsn_data[offset + 1] != 0x0F ||
               rsn_data[offset + 2] != 0xAC {
                offset += 4;
                continue;
            }

            let suite_type = rsn_data[offset + 3];
            if suite_type == 8 || suite_type == 9 {
                return true;
            }

            offset += 4;
        }

        false
    }



    fn process_vendor_element(data: &[u8], flags: &mut SecFlags) {
        if data.len() >= 4 &&
           data[0] == 0x00 &&
           data[1] == 0x50 &&
           data[2] == 0xF2 &&
           data[3] == 0x01 {
            flags.has_wpa = true;
            flags.is_open = false;
        }
    }



    fn process_privacy_element(data: &[u8], flags: &mut SecFlags) {
        if !data.is_empty() && data[0] & 0x10 != 0 {
            flags.has_wep = true;
            flags.is_open = false;
        }
    }

}



struct SecFlags {
    has_rsn: bool,
    has_wpa: bool,
    has_wep: bool,
    is_open: bool,
    is_wpa3: bool,
}

impl SecFlags {
    fn new() -> Self {
        SecFlags {
            has_rsn: false,
            has_wpa: false,
            has_wep: false,
            is_open: true,
            is_wpa3: false,
        }
    }

    fn to_sec_string(&self) -> String {
        if self.is_wpa3 {
            "WPA3".to_string()
        } else if self.has_rsn {
            "WPA2".to_string()
        } else if self.has_wpa {
            "WPA".to_string()
        } else if self.has_wep {
            "WEP".to_string()
        } else if self.is_open {
            "Open".to_string()
        } else {
            "Unknown".to_string()
        }
    }
}