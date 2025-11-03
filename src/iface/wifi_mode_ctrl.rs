use nl80211_ng::Nl80211;
use crate::iface::IfaceInfo;
use crate::utils::abort;



pub struct WifiModeController {
    iface_name: String,
    if_index:   u32,
    nl:         Nl80211,
}



impl WifiModeController {

    pub fn new(iface_name: &str) -> Self {
        let if_index = IfaceInfo::get_iface_index(iface_name);

        let nl = Nl80211::new().unwrap_or_else(|e| {
            abort(&format!("failed to initialize nl80211: {}", e));
        });

        WifiModeController {
            iface_name: iface_name.to_string(),
            if_index: if_index.try_into().unwrap(),
            nl,
        }
    }

    

    pub fn enable_monitor(&mut self) -> &mut Self {
        self.nl.set_interface_monitor(true, self.if_index).unwrap_or_else(|e| {
            abort(&format!(
                "failed to set interface '{}' (ifindex {}) to monitor: {}",
                self.iface_name, self.if_index, e
            ));
        });

        self.ensure_interface_is_up();
        self
    }

    

    pub fn disable_monitor(&mut self) -> &mut Self {
        self.nl.set_interface_station(self.if_index).unwrap_or_else(|e| {
            abort(&format!(
                "failed to set interface '{}' (ifindex {}) to station: {}",
                self.iface_name, self.if_index, e
            ));
        });

        self.ensure_interface_is_up();
        self
    }



    fn ensure_interface_is_up(&mut self) {
        self.nl.set_interface_up(self.if_index).unwrap_or_else(|e| {
            abort(&format!(
                "failed to bring interface '{}' up after setting station: {}",
                self.iface_name, e
            ));
        });
    }

}
