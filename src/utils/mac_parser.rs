use crate::utils::abort;



pub fn parse_mac(input: &str) -> Result<[u8; 6], String> {
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