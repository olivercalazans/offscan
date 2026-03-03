package ifaceinfo

import (
	"fmt"
	"net"
	"offscan/utils"
)



func IPv4(iface *net.Interface) (net.IP, error) {
    addrs, err := iface.Addrs()
    if err != nil {
        return nil, fmt.Errorf("Unable to get interface IPs: %w", err)
    }

    for _, addr := range addrs {
        ipNet, ok := addr.(*net.IPNet)
     
        if !ok {
            continue
        }
     
        ip := ipNet.IP
        if ip.To4() == nil {
            continue
        }
     
        return ip, nil
    }
    
    return nil, fmt.Errorf("No IPv4 address found on interface")
}



func MustIPv4(iface *net.Interface) net.IP {
    ip, err := IPv4(iface)

    if err != nil {
        utils.Abort(fmt.Sprintf("%v", err))
    }

    return ip
}