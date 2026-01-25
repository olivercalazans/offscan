use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::ffi::CStr;
use std::fs;
use libc::{ getifaddrs, freeifaddrs, ifaddrs, AF_INET, sockaddr_in };
use crate::iface::Iface;
use crate::utils::abort;



pub(crate) struct SysInfo;


impl SysInfo {

    pub fn ifaces() -> Vec<String> {
        let entries = fs::read_dir("/sys/class/net")
            .unwrap_or_else(|e| {
                abort(format!("Failed to read /sys/class/net: {}", e))
            });

        let interfaces: Vec<String> = entries
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    e.file_name().into_string().ok()
                })
            })
            .collect();
        
        interfaces
    }



    pub fn get_info(iface: &str, info_type: &str) -> Result<String, String> {
        let file_path = format!("/sys/class/net/{}/{}", iface, info_type);
        
        fs::read_to_string(&file_path)
            .map(|content| content.trim().to_string())
            .map_err(|e| format!("Failed to read {}: {}", file_path, e))
    }



    pub fn exists(iface_name: &str) -> Result<String, String> {
        let interfaces = Self::ifaces();
    
        if interfaces.iter().any(|iface| iface == iface_name) {
            Ok(iface_name.to_string())
        } else {
            Err("Network interface does not exist".to_string())
        }
    }



    pub fn ifaddrs_ptr() -> *mut ifaddrs {
        unsafe {
            let mut ifap: *mut ifaddrs = std::ptr::null_mut();

            if getifaddrs(&mut ifap) != 0 {
                abort(format!("getifaddrs failed: {}", std::io::Error::last_os_error()));
            }

            ifap
        }
    }



    pub fn iface_from_ip(dst_ip: Ipv4Addr) -> Iface {
        let ip = Self::src_ip_from_dst_ip(dst_ip);

        unsafe {
            let ifap    = Self::ifaddrs_ptr();
            let mut ptr = ifap;

            while !ptr.is_null() {
                let ifa = &*ptr;

                if ifa.ifa_addr.is_null() || (*ifa.ifa_addr).sa_family as i32 != AF_INET {
                    ptr = ifa.ifa_next;
                    continue;
                }

                let sockaddr   = &*(ifa.ifa_addr as *const sockaddr_in);
                let addr_bytes = sockaddr.sin_addr.s_addr.to_ne_bytes();
                let iface_ip   = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);

                if iface_ip == ip {
                    freeifaddrs(ifap);
                    let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
                    return Iface::new(&name);
                }

                ptr = ifa.ifa_next;
            }

            freeifaddrs(ifap);
            abort(format!("Could not find any iface with IP {}", ip));
        }
    }



    pub fn src_ip_from_dst_ip(dst_ip: Ipv4Addr) -> Ipv4Addr {
        let sockaddr = SocketAddrV4::new(dst_ip, 53);

        let sock = UdpSocket::bind(("0.0.0.0", 0))
            .unwrap_or_else(|e| abort(format!("Failed to bind UDP socket: {}", e)));

        sock.connect(sockaddr)
            .unwrap_or_else(|e| abort(format!("Failed to connect UDP socket: {}", e)));

        match sock.local_addr().unwrap().ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => abort("Expected a local IPv4 address, but got IPv6"),
        }
    }



    pub fn default_iface() -> Iface {
        Self::iface_from_ip(Ipv4Addr::new(8, 8, 8, 8))
    }

}