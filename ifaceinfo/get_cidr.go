package ifaceinfo

import (
	"fmt"
	"net"
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