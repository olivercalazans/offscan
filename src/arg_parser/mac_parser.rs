use crate::utils::abort;



pub fn parse_mac(s: &str) -> [u8; 6] {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        abort(format!("MAC address must have 6 colon-separated parts, received: '{}'", s));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            abort(format!("Each MAC part must be 2 hexadecimal characters, invalid part: '{}'", part));
        }
        
        mac[i] = u8::from_str_radix(part, 16)
            .unwrap_or_else(|_| abort(format!("Invalid hexadecimal in MAC address: '{}'", part)));
    }

    mac
}

