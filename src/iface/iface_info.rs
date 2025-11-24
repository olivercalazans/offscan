use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::ffi::{CStr};
use libc::{getifaddrs, freeifaddrs, ifaddrs, AF_INET, sockaddr_in};
use crate::utils::abort;



pub struct IfaceInfo;


impl IfaceInfo {

    pub fn get_iface_names() -> Vec<String> {
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



    pub fn check_iface_exists(iface_name: &str) -> Result<bool, String> {
        let interfaces = Self::get_iface_names();
    
        if interfaces.iter().any(|iface| iface == iface_name) {
            Ok(true)
        } else {
            Err("Network interface does not exist".to_string())
        }
    }



    pub fn get_iface_index(iface_name: &str) -> i32 {
        let ifindex_path = format!("/sys/class/net/{}/ifindex", iface_name);
        
        match fs::read_to_string(&ifindex_path) {
            Ok(content) => {
                content.trim().parse().unwrap_or_else(|_| {
                    abort(&format!("Failed to parse ifindex for interface: {}", iface_name));
                })
            }
            Err(_) => {
                abort(&format!("Interface not found or ifindex unavailable: {}", iface_name));
            }
        }
    }



    unsafe fn get_ifaddrs_ptr() -> *mut ifaddrs {
        unsafe {
            let mut ifap: *mut ifaddrs = std::ptr::null_mut();

            if getifaddrs(&mut ifap) != 0 {
                abort(format!("getifaddrs failed: {}", std::io::Error::last_os_error()));
            }

            ifap
        }
    }



    pub fn iface_name_from_ip(dst_ip: Ipv4Addr) -> String {
        let ip = Self::src_ip_from_dst_ip(dst_ip);
        unsafe {
            let ifap     = Self::get_ifaddrs_ptr();
            let mut ptr  = ifap;

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
                    return name;
                }

                ptr = ifa.ifa_next;
            }

            freeifaddrs(ifap);
            abort(format!("Could not find any interface with IP {}", ip));
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



    pub fn default_iface_name() -> String {
        Self::iface_name_from_ip(Ipv4Addr::new(8, 8, 8, 8))
    }



    pub fn iface_ip(iface_name: &str) -> Ipv4Addr {
        unsafe {
            let ifap    = Self::get_ifaddrs_ptr();
            let mut cur = ifap;

            while !cur.is_null() {
                let ifa       = &*cur;
                let name_cstr = CStr::from_ptr(ifa.ifa_name);
                let name      = name_cstr.to_string_lossy();

                if name != iface_name
                   || ifa.ifa_addr.is_null()
                   || (*ifa.ifa_addr).sa_family as i32 != AF_INET 
                {
                    cur = ifa.ifa_next;
                    continue;
                }

                let addr = &*(ifa.ifa_addr as *const sockaddr_in);
                let ip   = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                freeifaddrs(ifap);
                return ip;
            }

            freeifaddrs(ifap);
            abort(format!("Interface {} not found or has no IPv4 address", iface_name));
        }
    }



    pub fn iface_network_cidr(iface_name: &str) -> String {
        unsafe {
            let ifap    = Self::get_ifaddrs_ptr();
            let mut cur = ifap;

            while !cur.is_null() {
                let ifa       = &*cur;
                let name_cstr = CStr::from_ptr(ifa.ifa_name);
                let name      = name_cstr.to_string_lossy();

                if name != iface_name
                    || ifa.ifa_addr.is_null()
                    || ifa.ifa_netmask.is_null()
                    || (*ifa.ifa_addr).sa_family as i32 != AF_INET
                {
                    cur = ifa.ifa_next;
                    continue;
                }

                let addr = &*(ifa.ifa_addr as *const sockaddr_in);
                let ip   = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());

                let netmask = &*(ifa.ifa_netmask as *const sockaddr_in);
                let mask    = Ipv4Addr::from(netmask.sin_addr.s_addr.to_ne_bytes());

                freeifaddrs(ifap);

                let cidr        = mask.octets().iter().map(|b| b.count_ones()).sum::<u32>() as u8;
                let ip_u32      = u32::from(ip);
                let mask_u32    = u32::from(mask);
                let network_u32 = ip_u32 & mask_u32;
                let network     = Ipv4Addr::from(network_u32.to_be_bytes());

                return format!("{}/{}", network, cidr);
            }

            freeifaddrs(ifap);
            abort(format!("Interface {} not found or missing IPv4/netmask", iface_name));
        }
    }

}