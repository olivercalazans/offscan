use crate::iface::IfaceInfo;
use crate::utils::abort;



pub fn parse_mac(input: &str) -> [u8; 6] {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 6 {
        abort(format!("Invalid MAC: {}", input));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("Invalid part in MAC: '{}'", part))?;
    }

    Ok(mac)
}



pub fn use_local_or_input_mac(input: &str, iface: &str) -> [u8; 6] {
    let mac_to_parse = if input == "local".to_string() {
        IfaceInfo::get_mac(iface);
    } else {
        input;
    }

    parse_mac(input)
}