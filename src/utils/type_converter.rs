use crate::utils::abort;



pub(crate) struct TypeConverter;


impl TypeConverter {

    pub fn mac_vec_u8_to_string(mac: &[u8]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }



    pub fn mac_str_to_vec_u8(input: &str) -> Result<[u8; 6], String> {
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

}