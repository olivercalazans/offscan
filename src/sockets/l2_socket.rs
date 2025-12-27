use std::mem;
use std::io;
use libc::{
    socket, sendto, close, sockaddr_ll, htons, 
    AF_PACKET, SOCK_RAW, ETH_P_ALL, SOL_SOCKET, SO_BINDTODEVICE
};
use crate::iface::IfaceInfo;
use crate::utils::abort;



pub struct Layer2RawSocket {
    file_desc : i32,
    addr      : sockaddr_ll,
}


impl Layer2RawSocket {

    pub fn new(iface_name: &str) -> Self {
        let ifindex   = IfaceInfo::iface_index(iface_name);
        let file_desc = Self::create_socket(iface_name);
        let addr      = Self::build_sockaddr(ifindex);

        Self { file_desc, addr }
    }



    fn create_socket(iface_name: &str) -> i32 {
        unsafe {
            let file_desc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32);
            if file_desc < 0 {
                abort(&format!(
                    "Failed to create RAW layer 2 socket: {}",
                    io::Error::last_os_error()
                ));
            }

            if let Err(e) = Self::bind_to_interface(file_desc, iface_name) {
                let _ = close(file_desc);
                abort(&format!("Failed to bind socket to interface: {}", e));
            }

            if let Err(e) = Self::configure_socket(file_desc) {
                let _ = close(file_desc);
                abort(&format!("Failed to configure socket: {}", e));
            }

            file_desc
        }
    }



    fn bind_to_interface(file_desc: i32, iface_name: &str) -> io::Result<()> {
        unsafe {
            let ifname_bytes           = iface_name.as_bytes();
            let mut ifreq: libc::ifreq = mem::zeroed();
            
            for (i, &byte) in ifname_bytes.iter().enumerate() {
                if i < ifreq.ifr_name.len() {
                    ifreq.ifr_name[i] = byte as libc::c_char;
                }
            }

            if libc::setsockopt(
                file_desc,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                &ifreq as *const _ as *const libc::c_void,
                mem::size_of::<libc::ifreq>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }



    fn configure_socket(file_desc: i32) -> io::Result<()> {
        unsafe {
            let buf_size: i32 = 1024 * 1024; // 1MB
            if libc::setsockopt(
                file_desc,
                SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const _ as *const libc::c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }



    fn build_sockaddr(ifindex: i32) -> sockaddr_ll {
        unsafe {
            let mut addr: sockaddr_ll = mem::zeroed();
            addr.sll_family   = AF_PACKET as u16;
            addr.sll_protocol = htons(ETH_P_ALL as u16);
            addr.sll_ifindex  = ifindex;
            addr.sll_halen    = 6;
            addr
        }
    }



    #[inline]
    pub fn send(&self, frame: &[u8]) {
        unsafe {
            let ret = sendto(
                self.file_desc,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &self.addr as *const _ as *const libc::sockaddr,
                mem::size_of::<sockaddr_ll>() as libc::socklen_t,
            );

            if ret < 0 {
                abort(&format!("Failed to send frame: {}", io::Error::last_os_error()));
            }
        }
    }



    pub fn close(&mut self) {
        if self.file_desc >= 0 {
            unsafe {
                let _ = close(self.file_desc);
                self.file_desc = -1;
            }
        }
    }

}



impl Drop for Layer2RawSocket {
    fn drop(&mut self) {
        self.close();
    }
}