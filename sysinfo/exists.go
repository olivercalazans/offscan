package sysinfo

import (
	"fmt"
	"net"
	"offscan/utils"
)



func IfaceExist(name string) net.Interface {
    iface, err := net.InterfaceByName(name)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Network interface does not exist: %s", name))
    }

    return *iface
}