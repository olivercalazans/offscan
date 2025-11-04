pub struct PacketBuffer {
    pub packet: [u8; 69],
    pub layer4: [u8; 20],
    pub ip:     [u8; 20],
    pub ether:  [u8; 14],
}



impl Default for PacketBuffer {
    fn default() -> Self {
        Self {
            packet: [0; 69],
            layer4: [0; 20],
            ip:     [0; 20],
            ether:  [0; 14],
        }
    }
}
