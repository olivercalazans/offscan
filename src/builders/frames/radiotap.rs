pub struct Radiotap;


impl Radiotap {

    pub fn build_header(buffer: &mut [u8]) {
        buffer[0]  = 0x00; // Header revision
        buffer[1]  = 0x00; // Header pad
        buffer[2]  = 0x0c; // Header length
        buffer[3]  = 0x00; // 
        buffer[4]  = 0x04; // Bitmap
        buffer[5]  = 0x80; //
        buffer[6]  = 0x00; //
        buffer[7]  = 0x00; // 
        buffer[8]  = 0x02; // Rate
        buffer[9]  = 0x00; // Rate pad
        buffer[10] = 0x18; // TX flags
        buffer[11] = 0x00; // 
    }

}