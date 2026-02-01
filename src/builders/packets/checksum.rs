use std::net::Ipv4Addr;



pub(super) struct Checksum;


impl Checksum {

    fn calculate_checksum(mut sum: u32, data: &[u8]) -> u16 {
        let mut i = 0;
        
        while i + 1 < data.len() {
            sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
            i += 2;
        }
        
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        !(sum as u16)
    }

    

    pub fn tcp_udp_checksum(
        header   : &[u8],
        src_ip   : Ipv4Addr,
        dst_ip   : Ipv4Addr,
        protocol : u8,
    ) 
      -> u16
    {
        let mut sum    = 0u32;
        let src_octets = src_ip.octets();
        let dst_octets = dst_ip.octets();
        
        sum += ((src_octets[0] as u32) << 8 | src_octets[1] as u32)
             + ((src_octets[2] as u32) << 8 | src_octets[3] as u32);
        
        sum += ((dst_octets[0] as u32) << 8 | dst_octets[1] as u32)
             + ((dst_octets[2] as u32) << 8 | dst_octets[3] as u32);
        
        sum += protocol as u32;
        sum += header.len() as u32;
        
        Self::calculate_checksum(sum, header)
    }

    

    pub fn icmp_checksum(header: &[u8]) -> u16 {
        Self::calculate_checksum(0, header)
    }
    


    pub fn ipv4_checksum(header: &[u8]) -> u16 {
        Self::calculate_checksum(0, header)
    }
    
}