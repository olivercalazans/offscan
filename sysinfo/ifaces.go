package sysinfo

import (
	"fmt"
	"net"
	"offscan/utils"
)



func MustIfaces() []net.Interface {
	interfaces, err := net.Interfaces()
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to get interface list: %v", err))
    }

	return interfaces
}