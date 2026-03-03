package sysinfo

import (
	"fmt"
	"net"
	"offscan/ifaceinfo"
	"offscan/utils"
)



func ResolveMac(macStr string, iface *net.Interface) net.HardwareAddr {
    var mac net.HardwareAddr
    var err error

    switch macStr {
    case "":        return  nil
    case "gateway": mac, err = ifaceinfo.GatewayMAC(iface)
    case "local":   mac, err = iface.HardwareAddr, nil
    default:        mac, err = net.ParseMAC(macStr)
    }

    if err != nil {
        utils.Abort(fmt.Sprintf("Unable to parse MAC address: %v", err))
    }

    return mac
}



func MustResolveMac(macStr string, iface *net.Interface) net.HardwareAddr {
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