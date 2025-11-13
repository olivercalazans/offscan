use std::mem;
use libc::{socket, sendto, close, sockaddr_ll, htons, AF_PACKET, SOCK_RAW, ETH_P_ALL};
use crate::iface::IfaceInfo;
use crate::utils::abort;



pub struct Layer2RawSocket {
    file_desc: i32,
    addr:      sockaddr_ll,
}



impl Layer2RawSocket {

    pub fn new(iface_name: &str) -> Self {
        let ifindex   = IfaceInfo::get_iface_index(iface_name);
        let file_desc = Self::create_socket();
        let addr      = Self::build_sockaddr(ifindex);

        Self { file_desc, addr }
    }



    fn create_socket() -> i32 {
        unsafe {
            let file_desc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32);
            if file_desc < 0 {
                abort(&format!(
                    "Failed to create RAW layer 2 socket: {}",
                    std::io::Error::last_os_error()
                ));
            }

            file_desc
        }
    }



    fn build_sockaddr(ifindex: i32) -> sockaddr_ll {
        unsafe {
            let mut addr: sockaddr_ll = mem::zeroed();
            addr.sll_family   = AF_PACKET as u16;
            addr.sll_protocol = htons(ETH_P_ALL as u16);
            addr.sll_ifindex  = ifindex;
            addr
        }
    }



    #[inline]
    pub fn send(&self, frame: &[u8]) {
        unsafe {
            let ret = sendto(
                self.file_desc,
                frame.as_ptr() as *const _,
                frame.len(),
                0,
                &self.addr as *const _ as *const _,
                mem::size_of::<sockaddr_ll>() as u32,
            );

            if ret < 0 {
                abort(&format!("Failed to send frame: {}", std::io::Error::last_os_error()));
            }
        }
    }

}



impl Drop for Layer2RawSocket {

    fn drop(&mut self) {
        unsafe {
            let _ = close(self.file_desc);
        }
    }

}
