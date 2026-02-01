use std::time::{SystemTime, UNIX_EPOCH};
use crate::builders::ieee80211::Radiotap;
use crate::utils::{Bssid, abort};



pub(crate) struct Beacon {
    buffer : [u8; 119],
    len    : usize,
}


impl Beacon {

    pub fn new() -> Self {
        let buffer = Self::build_fixed();
        
        Self { buffer, len: 0, }
    }



    fn build_fixed() -> [u8; 119] {
        let mut buffer = [0u8; 119];

        Radiotap::minimal_header(&mut buffer[..12]);

        // HEADER (12 - 36)
        buffer[12] = 0x80; // Type/Subtype: Management Beacon
        buffer[13] = 0x00; // Flags: none
        buffer[14] = 0x00; // Duration
        buffer[15] = 0x00;

        buffer[16..22].copy_from_slice(&[0xFF; 6]); // Dst addr

        // BODY (36 ~ 119)
        buffer[44..46].copy_from_slice(&100u16.to_le_bytes());

        buffer
    }



    #[inline]
    pub fn beacon(
        &mut self,
        bssid   : Bssid,
        ssid    : &str,
        seq     : u16,
        channel : u8,
        sec     : &str,
    ) 
      -> &[u8]
    {
        self.beacon_header(bssid, seq);
        self.beacon_body(ssid, channel, sec);

        &self.buffer[..self.len]
    }



    #[inline]
    fn beacon_header(
        &mut self,
        bssid : Bssid,
        seq   : u16,
    ) {
        self.buffer[22..28].copy_from_slice(bssid.bytes());
        self.buffer[28..34].copy_from_slice(bssid.bytes());

        let bytes = {
            let seq_ctrl = (seq & 0x0FFF) << 4;
            seq_ctrl.to_le_bytes()
        };

        self.buffer[34]   = bytes[0];
        self.buffer[35]   = bytes[1]; // Fragment 0
    }



    #[inline]
    fn beacon_body(
        &mut self,
        ssid    : &str,
        channel : u8,
        sec     : &str,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        self.buffer[36..44].copy_from_slice(&timestamp.to_le_bytes());

        let (sec_flags, sec_data) = Self::get_sec_data(sec);

        self.buffer[46..48].copy_from_slice(&sec_flags);

        let ssid_bytes = ssid.as_bytes();
        let ssid_len   = ssid_bytes.len().min(32);
        let mut index  = 48;

        self.buffer[index]     = 0x00;  // Element ID (SSID)
        self.buffer[index + 1] = ssid_len as u8;
        index += 2;

        self.buffer[index..index + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
        index += ssid_len;

        self.buffer[index..index + 10].copy_from_slice(&[
            0x01, 0x08,             // ID 1, Length 8
            0x82, 0x84, 0x8B, 0x96, // 1, 2, 5.5, 11 Mbps
            0x0C, 0x12, 0x18, 0x24, // 6, 9, 12, 24 Mbps
        ]);
        index += 10;
        
        // IE 3: DS Parameter (channel)
        self.buffer[index..index + 3].copy_from_slice(&[0x03, 0x01, channel]);
        index += 3;
        
        // IE 5: TIM
        self.buffer[index..index + 6].copy_from_slice(&[0x05, 0x04, 0x00, 0x01, 0x00, 0x00]);
        index += 6;
        
        let len_sec_data = sec_data.len();
        self.buffer[index..index + len_sec_data].copy_from_slice(&sec_data);
        index += len_sec_data;

        // IE 50: Extended Supported Rates
        self.buffer[index..index + 6].copy_from_slice(&[0x32, 0x04, 0x30, 0x48, 0x60, 0x6C]);
        index += 6;

        self.len = index;
    }



    #[inline]
    fn get_sec_data(sec: &str) -> ([u8;2], Vec<u8>) {
        match sec {
            "open" => ([0x01, 0x04], vec![]),
            
            "wpa" => ([0x11, 0x04], vec![   // Vendor Specific IE (ID 221) for WPA
                0xDD, 0x16,                 // ID 221, Length 22
                0x00, 0x50, 0xF2,           // Microsoft OUI
                0x01, 0x01, 0x00, 0x00, 0x50, 0xF2, 0x02,  // WPA Information Element
                0x01, 0x00, 0x00, 0x50, 0xF2, 0x04,
                0x01, 0x00, 0x00, 0x50, 0xF2, 0x02,
                0x00, 0x00,
            ]),

            "wpa2" => ([0x11, 0x04], vec![  // RSN IE (ID 48) para WPA2
                0x30, 0x14,                 // ID 48, Length 20
                0x01, 0x00,                 // Version: 1
                0x00, 0x0F, 0xAC, 0x04,     // Group Cipher: CCMP
                0x01, 0x00,                 // Pairwise Cipher Count: 1
                0x00, 0x0F, 0xAC, 0x04,     // Pairwise Cipher: CCMP
                0x01, 0x00,                 // AKM Suite Count: 1
                0x00, 0x0F, 0xAC, 0x02,     // AKM Suite: PSK
                0x00, 0x00,                 // RSN Capabilities
            ]),

            "wpa3" => ([0x11, 0x04], vec![  // RSN IE (ID 48) para WPA3
                0x30, 0x18,                 // ID 48, Length 24
                0x02, 0x00,                 // Version: 2
                0x00, 0x0F, 0xAC, 0x0C,     // Group Cipher: GCMP-256
                0x01, 0x00,                 // Pairwise Cipher Count: 1
                0x00, 0x0F, 0xAC, 0x0C,     // Pairwise Cipher: GCMP-256
                0x01, 0x00,                 // AKM Suite Count: 1
                0x00, 0x0F, 0xAC, 0x06,     // AKM Suite: SAE
                0x00, 0x00,                 // RSN Capabilities
                0x00, 0x0F, 0xAC, 0x08,     // Management Group Cipher: BIP-GMAC-256
            ]),

            _ => abort(format!("Unknow security flag: {}", sec))
        }
    }

}