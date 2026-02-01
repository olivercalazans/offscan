use crate::iface::Iface;
use crate::utils::{abort, Mac};



pub(crate) fn resolve_mac(
    input_mac : Option<String>, 
    iface     : &Iface
) 
  -> Option<Mac>
{
    if input_mac.is_none() {
        return None;
    }

    let mac = input_mac.unwrap();

    let mac = match mac.as_str() {
        "gateway" => iface.gateway_mac().unwrap_or_else(|e| abort(e)),
        "local"   => iface.mac().unwrap_or_else(|e| abort(e)),
        _         => Mac::from_str(&mac).unwrap_or_else(|e| abort(e))
    };
    
    Some(mac)
}