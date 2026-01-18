// sys_sniff.rs
use std::{collections::BTreeMap, mem};
use crate::engines::wifi_map::WifiData;
use crate::utils::{TypeConverter, abort};


#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Info {
    bssid : [u8; 6],
    ssid  : [i8; 33],
    freq  : u32,
    security : [i8; 16],  // Adicionado campo security
}


unsafe extern "C" {
    fn scan_wifi(
        ifname  : *const i8,
        results : *mut *mut Info,
        count   : *mut i32,
    ) -> i32;

    fn free_scan_results(results: *mut Info);
}




pub(super) struct SysSniff<'a> {
    iface     : String,
    wifis_buf : &'a mut BTreeMap<String, WifiData>,
    buffer    : Vec<Info>,
}


impl<'a> SysSniff<'a> {

    pub fn new(
        iface     : String, 
        wifis_buf : &'a mut BTreeMap<String, WifiData>
    ) -> Self {
        Self { 
            iface, 
            wifis_buf,
            buffer : Vec::new(), 
        }
    }



    pub fn execute_sys_sniff(&mut self) {
        self.call_c_module();
        self.process_info();
    }



    fn call_c_module(&mut self) {
        unsafe {
            let iface = std::ffi::CString::new(self.iface.clone()).unwrap();

            let mut ptr: *mut Info = std::ptr::null_mut();
            let mut count: i32 = 0;

            let ret = scan_wifi(
                iface.as_ptr(),
                &mut ptr,
                &mut count,
            );

            if ret != 0 {
                abort(format!("Erro no scan: {}", ret));
            }

            let slice    = std::slice::from_raw_parts(ptr, count as usize);
            let sys_info = slice.iter().copied().map(Into::into).collect();

            free_scan_results(ptr);
            self.buffer = sys_info;
        }
    }



    fn process_info(&mut self) {
        let sys_info = mem::take(&mut self.buffer);

        for info in sys_info.into_iter() {
            let ssid     = Self::ssid_to_string(&info.ssid);
            let bssid    = TypeConverter::mac_vec_u8_to_string(&info.bssid);
            let chnl     = Self::freq_to_channel(info.freq);
            let freq     = Self::get_frequency(chnl);
            let security = Self::security_to_string(&info.security);  // Nova função

            self.add_info(ssid, bssid, chnl, freq, security)
        }
    }



    fn ssid_to_string(ssid: &[i8]) -> String {
        let bytes: Vec<u8> = ssid
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();

        String::from_utf8_lossy(&bytes).to_string()
    }



    fn security_to_string(security: &[i8]) -> String {
        let bytes: Vec<u8> = security
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();

        String::from_utf8_lossy(&bytes).to_string()
    }



    fn freq_to_channel(freq: u32) -> u8 {
        match freq {
            2412..=2472 => ((freq - 2407) / 5) as u8,
            2484        => 14,
            5000..=5900 => ((freq - 5000) / 5) as u8,
            _           => 0,
        }
    }



    fn get_frequency(chnl: u8) -> String {
        if chnl <= 14 {"2.4".to_string()} else {"5".to_string()}
    }



    #[inline]
    fn add_info(
        &mut self, 
        ssid     : String, 
        bssid    : String, 
        chnl     : u8, 
        freq     : String,
        security : String,  // Novo parâmetro
    ) {
        self.wifis_buf
            .entry(ssid)
            .and_modify(|existing_info| {
                existing_info.bssids.insert(bssid.clone());
            })
            .or_insert_with(|| {
                WifiData::new(bssid, chnl, freq.to_string(), security)  // Passa segurança
            });
    }

}