use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use libc::{
    addrinfo, freeaddrinfo, getnameinfo, getaddrinfo, 
    NI_NAMEREQD, NI_MAXHOST, AF_UNSPEC, AI_NUMERICHOST
};



pub(crate) fn get_host_name(ip: &str) -> String {
    unsafe {
        let mut hints: addrinfo = std::mem::zeroed();
        hints.ai_family         = AF_UNSPEC;
        hints.ai_flags          = AI_NUMERICHOST;

        let mut res: *mut addrinfo = ptr::null_mut();

        if getaddrinfo(ip.as_ptr() as *const i8, ptr::null(), &hints, &mut res) != 0 {
            return "Unknown".to_string();
        }

        let mut host = [0 as c_char; NI_MAXHOST as usize];
        let err = getnameinfo(
            (*res).ai_addr,
            (*res).ai_addrlen,
            host.as_mut_ptr(),
            NI_MAXHOST as u32,
            ptr::null_mut(),
            0,
            NI_NAMEREQD,
        );

        freeaddrinfo(res);

        if err != 0 {
            return "Unknown".to_string();
        }

        let c_str    = CStr::from_ptr(host.as_ptr());
        let hostname = c_str.to_string_lossy().into_owned();
        
        if hostname.ends_with(".lan") {
            return hostname.trim_end_matches(".lan").to_string();
        }

        hostname
    }
}
