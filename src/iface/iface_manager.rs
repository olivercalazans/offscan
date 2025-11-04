use std::{ffi::CString, io, os::unix::io::RawFd, process::Command, mem, format};
use libc;
use crate::utils::abort;



pub struct InterfaceManager;



impl InterfaceManager {

    fn create_socket() -> RawFd {
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                abort(&format!("Failed to create socket: {}", io::Error::last_os_error()));
            }
            sock
        }
    }



    fn set_interface_flags(sock: RawFd, iface_name: &str, up: bool) {
        let c_interface = CString::new(iface_name).unwrap_or_else(|e| {
            abort(&format!("Invalid interface name '{}': {}", iface_name, e));
        });

        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        
        unsafe {
            std::ptr::copy_nonoverlapping(
                c_interface.as_ptr(),
                ifr.ifr_name.as_mut_ptr(),
                iface_name.len().min(ifr.ifr_name.len() - 1)
            );
        }

        if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) } < 0 {
            unsafe { libc::close(sock) };
            abort(&format!("Failed to get flags for interface '{}': {}", iface_name, io::Error::last_os_error()));
        }

        unsafe {
            let current_flags = ifr.ifr_ifru.ifru_flags;
            if up {
                ifr.ifr_ifru.ifru_flags = current_flags | (libc::IFF_UP as i16);
            } else {
                ifr.ifr_ifru.ifru_flags = current_flags & !(libc::IFF_UP as i16);
            }
        }

        if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS, &mut ifr) } < 0 {
            unsafe { libc::close(sock) };
            abort(&format!("Failed to set flags for interface '{}': {}", iface_name, io::Error::last_os_error()));
        }

        unsafe { libc::close(sock) };
    }



    pub fn set_iface_up(iface_name: &str) {
        let sock = Self::create_socket();
        Self::set_interface_flags(sock, iface_name, true);
    }



    pub fn set_iface_down(iface_name: &str) {
        let sock = Self::create_socket();
        Self::set_interface_flags(sock, iface_name, false);
    }

    
    
    pub fn enable_monitor_mode(iface_name: &str) {
        Self::set_iface_down(iface_name);
        
        let output = Command::new("sudo")
            .args(&["iw", "dev", iface_name, "set", "type", "monitor"])
            .output()
            .unwrap_or_else(|e| {
                abort(&format!("Failed to execute iw command for '{}': {}", iface_name, e));
            });

        if !output.status.success() {
            abort(&format!(
                "Failed to enable monitor mode for '{}': {}",
                iface_name,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Self::set_iface_up(iface_name);
    }

    
    
    pub fn disable_monitor_mode(iface_name: &str) {
        Self::set_iface_down(iface_name);
        
        let output = Command::new("sudo")
            .args(&["iw", "dev", iface_name, "set", "type", "managed"])
            .output()
            .unwrap_or_else(|e| {
                abort(&format!("Failed to execute iw command for '{}': {}", iface_name, e));
            });

        if !output.status.success() {
            abort(&format!(
                "Failed to disable monitor mode for '{}': {}",
                iface_name,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Self::set_iface_up(iface_name);
    }

}