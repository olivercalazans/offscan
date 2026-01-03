use std::ffi::CString;



unsafe extern "C" {
    fn set_wifi_channel(interface_name: *const libc::c_char, channel: libc::c_int) -> libc::c_int;
}


pub struct IfaceManager;


impl IfaceManager {

    pub fn set_channel(iface: &str, channel: u32) -> bool {
        let c_iface   = CString::new(iface).expect("CString::new failed");
        let c_channel = channel as i32;

        unsafe {
            let result = set_wifi_channel(c_iface.as_ptr(), c_channel);
            if result != 0 {
                return false;
            }
        }

        true
    }

}