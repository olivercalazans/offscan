use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::ffi::{CStr, CString};
use libc::{getifaddrs, freeifaddrs, ifaddrs, AF_INET, sockaddr_in, if_nametoindex};
use crate::utils::abort;



pub struct IfaceInfo;



impl IfaceInfo {

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

                if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == AF_INET {
                    let sockaddr   = &*(ifa.ifa_addr as *const sockaddr_in);
                    let addr_bytes = sockaddr.sin_addr.s_addr.to_ne_bytes();
                    let iface_ip   = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);

                    if iface_ip == ip {
                        freeifaddrs(ifap);
                        let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
                        return name;
                    }
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

                if name == iface_name && !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == AF_INET {
                    let addr = &*(ifa.ifa_addr as *const sockaddr_in);
                    let ip   = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                    freeifaddrs(ifap);
                    return ip;
                }

                cur = ifa.ifa_next;
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

                if name == iface_name
                    && !ifa.ifa_addr.is_null()
                    && !ifa.ifa_netmask.is_null()
                    && (*ifa.ifa_addr).sa_family as i32 == AF_INET
                {
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

                cur = ifa.ifa_next;
            }

            freeifaddrs(ifap);
            abort(format!("Interface {} not found or missing IPv4/netmask", iface_name));
        }
    }



    pub fn get_iface_index(iface_name: &str) -> i32 {
        unsafe {
            let c_name = CString::new(iface_name).unwrap_or_else(|_| {
                abort(&format!("Invalid interface name: {}", iface_name));
            });

            let ifindex = if_nametoindex(c_name.as_ptr()) as i32;
            if ifindex == 0 {
                abort(&format!("Interface not found: {}", iface_name));
            }

            ifindex
        }
    }



    pub fn check_iface_exists(interface_name: &str) -> Result<String, String> {
        let ifname = CString::new(interface_name)
            .map_err(|_| "Invalid interface name containing null byte".to_string())?;

        let sock = unsafe { libc::socket(AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err("Failed to create socket for interface check".to_string());
        }

        #[repr(C)]
        struct IFReq {
            ifr_name: [libc::c_char; libc::IF_NAMESIZE],
            ifr_flags: libc::c_short,
        }

        let mut ifr: IFReq = unsafe { std::mem::zeroed() };
        unsafe {
            libc::strcpy(
                ifr.ifr_name.as_mut_ptr(),
                ifname.as_ptr() as *const libc::c_char,
            );
        }

        let result = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) };

        unsafe { libc::close(sock); }

        if result == 0 {
            return Ok(interface_name.to_string());
        }

        let io_error = std::io::Error::last_os_error();
        if io_error.raw_os_error() == Some(libc::ENODEV) {
            return Err("Network interface does not exist".to_string());
        }

        Err("Failed to check network interface status".to_string())
    }
}