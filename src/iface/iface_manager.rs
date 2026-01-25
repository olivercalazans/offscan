use std::ffi::CString;
use crate::utils::abort;



unsafe extern "C" {
    fn set_wifi_channel(
        interface_name: *const libc::c_char, 
        channel: libc::c_int
    ) -> libc::c_int;
}


pub(crate) struct IfaceManager;


impl IfaceManager {

    pub fn set_channel(iface: &str, channel: i32) -> bool {
        let c_iface = CString::new(iface)
            .unwrap_or_else(|e| abort(e.to_string()));

        unsafe {
            let result = set_wifi_channel(c_iface.as_ptr(), channel);
            if result != 0 {
                return false;
            }
        }

        true
    }

}