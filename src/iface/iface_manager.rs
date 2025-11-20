use std::{
    ffi::CString, io::Error, os::unix::io::RawFd, process::{Command, Output, Stdio},
    thread, time::Duration, mem, format, ptr::copy_nonoverlapping
};
use libc::{AF_INET, SOCK_DGRAM, socket, ifreq, ioctl, close, SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP};
use crate::utils::abort;



pub struct InterfaceManager;



impl InterfaceManager {

    fn create_socket() -> RawFd {
        unsafe {
            let sock = socket(AF_INET, SOCK_DGRAM, 0);
            if sock < 0 {
                abort(&format!("Failed to create socket: {}", Error::last_os_error()));
            }
            sock
        }
    }



    fn set_interface_flags(sock: RawFd, iface: &str, up: bool) {
        let c_interface = CString::new(iface).unwrap_or_else(|e| {
            abort(&format!("Invalid interface name '{}': {}", iface, e));
        });

        let mut ifr: ifreq = unsafe { mem::zeroed() };
        
        unsafe {
            copy_nonoverlapping(
                c_interface.as_ptr(),
                ifr.ifr_name.as_mut_ptr(),
                iface.len().min(ifr.ifr_name.len() - 1)
            );
        }

        if unsafe { ioctl(sock, SIOCGIFFLAGS, &mut ifr) } < 0 {
            unsafe { close(sock) };
            abort(&format!("Failed to get flags for interface '{}': {}", iface, Error::last_os_error()));
        }

        unsafe {
            let current_flags = ifr.ifr_ifru.ifru_flags;
            if up {
                ifr.ifr_ifru.ifru_flags = current_flags | (IFF_UP as i16);
            } else {
                ifr.ifr_ifru.ifru_flags = current_flags & !(IFF_UP as i16);
            }
        }

        if unsafe { ioctl(sock, SIOCSIFFLAGS, &mut ifr) } < 0 {
            unsafe { close(sock) };
            abort(&format!("Failed to set flags for interface '{}': {}", iface, Error::last_os_error()));
        }

        unsafe { close(sock) };
    }



    pub fn set_iface_up(iface: &str) {
        let sock = Self::create_socket();
        Self::set_interface_flags(sock, iface, true);
    }



    pub fn set_iface_down(iface: &str) {
        let sock = Self::create_socket();
        Self::set_interface_flags(sock, iface, false);
    }



    fn delete_iface(iface: &str) {
        let _ = Command::new("sudo")
            .args(&["iw", "dev", iface, "del"])
            .status();

        thread::sleep(Duration::from_millis(500));
    }



    fn change_iface_mode(iface: &str, mode: &str) -> Output {
        Command::new("sudo")
            .args(&["iw", "phy", "phy0", "interface", "add", iface, "type", mode])
            .output()
            .unwrap_or_else(|e| {
                abort(&format!("Failed to add monitor interface '{}': {}", iface, e));
            })
    }

    
    
    pub fn enable_monitor_mode(iface: &str) {        
        Self::set_iface_down(iface);
        Self::delete_iface(iface);
        
        let output = Self::change_iface_mode(iface, "monitor");

        if !output.status.success() {
            let output = Command::new("sudo")
                .args(&["iw", "dev", iface, "set", "type", "monitor"])
                .output()
                .unwrap_or_else(|e| {
                    abort(&format!("Failed to set monitor type for '{}': {}", iface, e));
                });

            if !output.status.success() {
                abort(&format!(
                    "Failed to enable monitor mode for '{}': {}",
                    iface,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }

        Self::set_iface_up(iface);
    }

    
    
    pub fn disable_monitor_mode(iface: &str) {
        Self::set_iface_down(iface);
        Self::delete_iface(iface);
                
        let output = Self::change_iface_mode(iface, "managed");

        if !output.status.success() {
            abort(&format!(
                "Failed to disable monitor mode for '{}': {}",
                iface,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Self::set_iface_up(iface);
    }



    pub fn set_channel(iface: &str, channel: u32) -> bool {
        let output = Command::new("sudo")
            .args(&["iw", "dev", iface, "set", "channel", &channel.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if output.is_err() {
            return false;
        }

        true
    }

}