package ifaceinfo

import (
	"fmt"
	"net"
	"offscan/utils"
)



func CIDR(iface *net.Interface) (string, error) {
    addrs, err := iface.Addrs()
    
	if err != nil {
        return "", err
    }
    
	for _, addr := range addrs {
        ipnet, ok := addr.(*net.IPNet)
    
		if !ok {
            continue
        }
    
		if ipnet.IP.To4() != nil {
            return ipnet.String(), nil
        }
    }
    
	return "", fmt.Errorf("No IPv4 address found")
}



func MustCIDR(iface *net.Interface) string {
    cidr, err := CIDR(iface)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to get CIDR for interface %s: %v", iface.Name, err))
    }

    return cidr
}