use std::{fmt, marker::PhantomData};



#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct Address<T> {
    bytes : [u8; 6],
    _kind : PhantomData<T>,
}


impl<T> Address<T> {
    
    pub fn new(bytes: [u8; 6]) -> Self {
        Self { bytes, _kind: PhantomData, }
    }



    pub fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(format!("Invalid address: {}", s));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| format!("Invalid part '{}'", part))?;
        }

        Ok(Self::new(bytes))
    }

    

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.try_into().unwrap())
    }



    pub fn bytes(&self) -> &[u8; 6] {
        &self.bytes
    }
}



impl<T> fmt::Display for Address<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!( f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bytes[0], self.bytes[1], self.bytes[2],
            self.bytes[3], self.bytes[4], self.bytes[5]
        )
    }
}


#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum MacAddr {}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum BssidAddr {}

pub type Mac   = Address<MacAddr>;
pub type Bssid = Address<BssidAddr>;
