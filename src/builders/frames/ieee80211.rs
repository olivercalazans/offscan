use std::time::{SystemTime, UNIX_EPOCH};
use crate::addrs::Bssid;
use crate::utils::abort;


pub(super) struct Ieee80211;


impl Ieee80211 {
    
    #[inline]
    pub fn deauth(
        buffer  : &mut [u8],
        src_mac : &[u8; 6],
        dst_mac : &[u8; 6], 
        bssid   : Bssid,
        seq     : u16,
    ) {
        buffer[0] = 0xC0;
        buffer[1] = 0x00;
        buffer[2] = 0x3a;
        buffer[3] = 0x01;

        buffer[4..10].copy_from_slice(dst_mac);
        buffer[10..16].copy_from_slice(src_mac);
        buffer[16..22].copy_from_slice(bssid.bytes());

        let seq_ctrl = ((seq & 0x0FFF) << 4) | 0x00;
        buffer[22..24].copy_from_slice(&seq_ctrl.to_le_bytes());
        
        buffer[24] = 0x0007;
        buffer[25] = 0x00;
    }
    


    #[inline]
    pub fn beacon_header(
        buffer : &mut [u8],
        bssid  : Bssid,
        seq    : u16,
    ) {
        buffer[0] = 0x80; // Type/Subtype: Management Beacon
        buffer[1] = 0x00; // Flags: none

        buffer[2] = 0x00; // Duration
        buffer[3] = 0x00;

        buffer[4..10].copy_from_slice(&[0xFF; 6]);
        buffer[10..16].copy_from_slice(bssid.bytes());
        buffer[16..22].copy_from_slice(bssid.bytes());

        let seq_ctrl = (seq & 0x0FFF) << 4;
        let bytes    = seq_ctrl.to_le_bytes();
        buffer[22]   = bytes[0];
        buffer[23]   = bytes[1]; // Fragment 0
    }



    #[inline]
    pub fn beacon_body(
        buffer  : &mut [u8],
        ssid    : &str,
        channel : u8,
        sec     : &str,
    ) -> usize
    {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        buffer[..8].copy_from_slice(&timestamp.to_le_bytes());
        buffer[8..10].copy_from_slice(&100u16.to_le_bytes());

        let (sec_flags, sec_data) = Self::get_sec_data(sec);

        buffer[10..12].copy_from_slice(&sec_flags);

        let ssid_bytes = ssid.as_bytes();
        let ssid_len   = ssid_bytes.len().min(32);
        let mut index  = 12;

        buffer[index]     = 0x00;  // Element ID (SSID)
        buffer[index + 1] = ssid_len as u8;
        index += 2;

        buffer[index..index + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
        index += ssid_len;

        buffer[index..index + 10].copy_from_slice(&[
            0x01, 0x08,             // ID 1, Length 8
            0x82, 0x84, 0x8B, 0x96, // 1, 2, 5.5, 11 Mbps
            0x0C, 0x12, 0x18, 0x24, // 6, 9, 12, 24 Mbps
        ]);
        index += 10;
        
        // IE 3: DS Parameter (channel)
        buffer[index..index + 3].copy_from_slice(&[0x03, 0x01, channel]);
        index += 3;
        
        // IE 5: TIM
        buffer[index..index + 6].copy_from_slice(&[0x05, 0x04, 0x00, 0x01, 0x00, 0x00]);
        index += 6;
        
        let len_sec_data = sec_data.len();
        buffer[index..index + len_sec_data].copy_from_slice(&sec_data);
        index += len_sec_data;

        // IE 50: Extended Supported Rates
        buffer[index..index + 6].copy_from_slice(&[0x32, 0x04, 0x30, 0x48, 0x60, 0x6C]);
        index += 6;

        index
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