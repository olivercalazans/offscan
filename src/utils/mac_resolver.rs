use crate::addrs::Mac;
use crate::iface::IfaceInfo;
use crate::utils::abort;



pub(crate) fn resolve_mac(
    input_mac : Option<String>, 
    iface     : &str
) 
  -> Option<Mac>
{
    if input_mac.is_none() {
        return None;
    }

    let mac = input_mac.unwrap();

    let mac = match mac.as_str() {
        "gateway" => IfaceInfo::gateway_mac(iface).unwrap().to_string(),
        "local"   => IfaceInfo::mac(iface),
        _         => mac
    };

    let mac = Mac::from_str(&mac)
        .unwrap_or_else(|e| abort(e));
    
    Some(mac)
}