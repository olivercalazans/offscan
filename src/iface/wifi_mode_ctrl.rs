use neli::consts::{
    nl::Nlmsg, genl::GenlId, genl::Nl80211Cmd, nl80211::Nl80211Attr, nl80211::Nl80211IfType
};
use neli::genl::Genlmsghdr;
use neli::nl::{Nlmsghdr, NlmF};
use neli::socket::NlSocketHandle;
use neli::types::GenlBuffer;
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use crate::utils::{abort, get_iface_index};



pub struct WifiModeController {
    iface_name: String,
    if_index:   u32,
    nl_socket:  NlSocketHandle,
}



impl WifiModeController {

    pub fn new(iface_name: &str) -> Self {
        let if_index = get_iface_index(iface_name);

        let mut sock = NlSocketHandle::connect(Nlmsg::Noop, None, &[])
            .unwrap_or_else(|e| abort(&format!("Unable to connect to nl80211 socket: {:?}", e)));

        let family_id = sock
            .resolve_genl_family("nl80211")
            .unwrap_or_else(|e| abort(&format!("Unable to resolve nl80211 family: {:?}", e)));

        sock.set_family_id(family_id);

        WifiModeController {
            iface_name: iface_name.to_string(),
            if_index,
            nl_socket: sock,
        }
    }

    
    
    pub fn set_monitor_mode(&mut self) -> &mut Self {
        let attrs = vec![
            neli::nlattr::Nlattr::new(None, Nl80211Attr::IfIndex, self.if_index).unwrap(),
            neli::nlattr::Nlattr::new(None, Nl80211Attr::IfType, Nl80211IfType::Monitor).unwrap(),
        ];
        let genlhdr = Genlmsghdr::new(
            Nl80211Cmd::SetInterface,
            0,
            GenlBuffer::from(attrs),
        ).unwrap_or_else(|e| abort(&format!("Failed to build genl message: {:?}", e)));

        let nlhdr = Nlmsghdr::new(
            None,
            self.nl_socket.family_id().unwrap(),
            NlmF::REQUEST | NlmF::ACK,
            None,
            None,
            genlhdr,
        );

        self.nl_socket.send_nl(nlhdr)
            .unwrap_or_else(|e| abort(&format!("Failed to send monitor command: {:?}", e)));
        self.nl_socket.recv_ack()
            .unwrap_or_else(|e| abort(&format!("No ACK received for monitor command: {:?}", e)));

        self
    }

    
    
    pub fn set_managed_mode(&mut self) -> &mut Self {
        let attrs = vec![
            neli::nlattr::Nlattr::new(None, Nl80211Attr::IfIndex, self.if_index).unwrap(),
            neli::nlattr::Nlattr::new(None, Nl80211Attr::IfType, Nl80211IfType::Station).unwrap(),
        ];
        let genlhdr = Genlmsghdr::new(
            Nl80211Cmd::SetInterface,
            0,
            GenlBuffer::from(attrs),
        ).unwrap_or_else(|e| abort(&format!("Failed to build genl message (managed): {:?}", e)));

        let nlhdr = Nlmsghdr::new(
            None,
            self.nl_socket.family_id().unwrap(),
            NlmF::REQUEST | NlmF::ACK,
            None,
            None,
            genlhdr,
        );

        self.nl_socket.send_nl(nlhdr)
            .unwrap_or_else(|e| abort(&format!("Failed to send managed command: {:?}", e)));
        self.nl_socket.recv_ack()
            .unwrap_or_else(|e| abort(&format!("No ACK received for managed command: {:?}", e)));

        self
    }

}
