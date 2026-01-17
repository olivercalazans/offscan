use crate::iface::IfaceInfo;
use crate::utils::{TypeConverter, abort};



pub(crate) fn resolve_mac(
    input_mac : Option<String>, 
    iface     : &str
) 
  -> Option<[u8; 6]>
{
    if input_mac.is_none() {
        return None;
    }

    let mac = input_mac.unwrap();

    let mac_to_parse = match mac.as_str() {
        "gateway" => IfaceInfo::gateway_mac(iface).unwrap().to_string(),
        "local"   => IfaceInfo::mac(iface),
        _         => mac
    };

    let mac = TypeConverter::mac_str_to_vec_u8(&mac_to_parse)
        .unwrap_or_else(|e| abort(e));
    
    Some(mac)
}