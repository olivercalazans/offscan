package sysinfo

import (
	"fmt"
	"net"
	"offscan/iface"
	"offscan/utils"
)



func ResolveMac(inputMac *string, iface *iface.Iface) net.HardwareAddr {
    if inputMac == nil {
        return nil
    }

    macStr := *inputMac
    var mac net.HardwareAddr
    var err error

    switch macStr {
    	case "gateway": mac, err = iface.GatewayMAC()
    	case "local":   mac, err = iface.MAC(), nil
    	default:        mac, err = net.ParseMAC(macStr)
    }

    if err != nil {
        utils.Abort(fmt.Sprintf("Uneable to pasr MAC address: %v", err))
    }

    return mac
}