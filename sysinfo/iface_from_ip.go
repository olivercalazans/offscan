package sysinfo

import (
	"fmt"
	"net"
	"offscan/utils"
)


func MustRouteIfaceForDstIP(dstIP net.IP) *net.Interface {
    dstIPv4 := dstIP.To4()
    if dstIPv4 == nil {
        utils.Abort(fmt.Sprintf("Destination IP is not IPv4: %s", dstIP))
    }

    dstAddr   := &net.UDPAddr{IP: dstIPv4, Port: 0}
    conn, err := net.DialUDP("udp", nil, dstAddr)
   
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to dial %s: %v", dstIPv4, err))
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    localIP := localAddr.IP.To4()

    if localIP == nil {
        utils.Abort(fmt.Sprintf("Local address is not IPv4: %v", localAddr.IP))
    }


    interfaces, err := net.Interfaces()
    if err != nil {
        utils.Abort(fmt.Sprintf("failed to list interfaces: %v", err))
    }

    for _, iface := range interfaces {
        if iface.Flags & net.FlagUp == 0 {
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
            if ipNet.IP.Equal(localIP) {
                return &iface
            }
        }
    }

    utils.Abort(fmt.Sprintf("no interface found with IP %s", localIP))
    return nil
}