package sysinfo

import (
	"fmt"
	"net"
	"offscan/ifaceinfo"
	"offscan/utils"
)



func ResolveMac(inputMac *string, iface *net.Interface) net.HardwareAddr {
    if inputMac == nil {
        return nil
    }

    macStr := *inputMac
    var mac net.HardwareAddr
    var err error

    switch macStr {
    	case "gateway": mac, err = ifaceinfo.GatewayMAC(iface)
    	case "local":   mac, err = iface.HardwareAddr, nil
    	default:        mac, err = net.ParseMAC(macStr)
    }

    if err != nil {
        utils.Abort(fmt.Sprintf("Unable to parse MAC address: %v", err))
    }

    return mac
}