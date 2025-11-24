use std::collections::HashMap;
use crate::iface::IfaceInfo;
use crate::utils::abort;



pub struct NetworkInfo {
    iface: HashMap<String, Info>,
}


struct Info {
    ip:       String,
    mac:      String,
    gateway:  String,
    cidr:     String,
    host_len: u32,
}



impl NetworkInfo {

    pub fn new() -> Self {
        Self { iface: HashMap::new(), }
    }


    pub fn execute(&self) {
        let i = IfaceInfo::get_iface_names();
        println!("{:?}", i);
    }

}