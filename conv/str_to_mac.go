package conv

import (
	"fmt"
	"net"
	"offscan/utils"
)



func MustStrToMac(macStr string) net.HardwareAddr {    
	mac, err := net.ParseMAC(macStr)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to parse MAC address: %v", err))
    }

	return mac
}