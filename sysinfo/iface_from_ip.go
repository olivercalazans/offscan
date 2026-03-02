package sysinfo

import (
	"net"
	"offscan/utils"
)



func MustRouteIfaceForDstIP(ip net.IP) *net.Interface {
    if ip.To4() == nil {
        utils.Abort("Expected an IPv4 address, but got IPv6")
    }

    interfaces := MustAllIfaces()

    for _, iface := range interfaces {
        if iface.Flags&net.FlagUp == 0 {
            continue
        }

        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)

			if !ok {
                continue
            }

			if ipNet.IP.Equal(ip) {
                return &iface
            }
        }
    }

    utils.Abort("Could not find any interface with IP " + ip.String())
    return nil
}