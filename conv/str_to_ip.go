package conv

import (
	"fmt"
	"net"
	"offscan/utils"
)



func MustStrToIPv4(s string) net.IP {
    ip := net.ParseIP(s)
    
	if ip == nil {
        utils.Abort(fmt.Sprintf("invalid IP address: %s", s))
    }
    
	return ip
}