use std::time::{SystemTime, UNIX_EPOCH};



pub(super) struct Ieee80211;


impl Ieee80211 {
    
    #[inline]
    pub fn deauth(
        buffer  : &mut [u8],
        src_mac : [u8; 6],
        dst_mac : [u8; 6], 
        bssid   : [u8; 6],
        seq     : u16,
    ) {
        buffer[0] = 0xC0;
        buffer[1] = 0x00;
        buffer[2] = 0x3a;
        buffer[3] = 0x01;

        buffer[4..10].copy_from_slice(&dst_mac);
        buffer[10..16].copy_from_slice(&src_mac);
        buffer[16..22].copy_from_slice(&bssid);

        let seq_ctrl = ((seq & 0x0FFF) << 4) | 0x00;
        buffer[22..24].copy_from_slice(&seq_ctrl.to_le_bytes());
        
        buffer[24] = 0x0007;
        buffer[25] = 0x00;
    }
    


    #[inline]
    pub fn beacon_header(
        buffer : &mut [u8],
        bssid  : [u8; 6],
        seq    : u16,
    ) {
        buffer[0] = 0x80; // Type/Subtype: Management Beacon
        buffer[1] = 0x00; // Flags: none

        buffer[2] = 0x00; // Duration
        buffer[3] = 0x00;

        buffer[4..10].copy_from_slice(&[0xFF; 6]);
        buffer[10..16].copy_from_slice(&bssid);
        buffer[16..22].copy_from_slice(&bssid);

        let seq_ctrl = (seq & 0x0FFF) << 4;
        let bytes    = seq_ctrl.to_le_bytes();
        buffer[22]   = bytes[0];
        buffer[23]   = bytes[1]; // Fragment 0
    }



    #[inline]
    pub fn beacon_body(
        buffer : &mut [u8],
        ssid   : &str,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        
        buffer[..8].copy_from_slice(&timestamp.to_le_bytes());
        buffer[8..10].copy_from_slice(&100u16.to_le_bytes());
        buffer[10..12].copy_from_slice(&[0x01, 0x04]);

        let ssid_bytes = ssid.to_bytes();
        let ssid_len   = ssid_bytes.len().min(32);
        let mut index  = 14 + ssid_len;
        
        buffer[12] = 0x00;  // Element ID (SSID)
        buffer[13] = ssid_len as u8;
        buffer[14..index] = copy_from_slice(&ssid_bytes);

        buffer[index..index + 8].copy_from_slice(&[
            0x01, 0x08,             // ID 1, Length 8
            0x82, 0x84, 0x8B, 0x96, // 1, 2, 5.5, 11 Mbps
            0x0C, 0x12, 0x18, 0x24, // 6, 9, 12, 24 Mbps
        ]);
        index += 8;

        // DS Parameter (channel)
        buffer[index..index + 3].copy_from_slice(&[0x03, 0x01, channel]);
        index += 3;

        // TIM
        buffer[index..index + 6].copy_from_slice(&[0x05, 0x04, 0x00, 0x01, 0x00, 0x00]);
        index += 6;
    
        // Extended Rates (opcional)
        buffer[index..index + 6].copy_from_slice(&[0x32, 0x04, 0x30, 0x48, 0x60, 0x6C]);
    }

}