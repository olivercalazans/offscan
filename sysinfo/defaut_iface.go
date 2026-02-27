package sysinfo

import (
	"fmt"
	"net"
	"offscan/utils"
)



func MustDefaultInterface() string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to bind UDP socket: %v", err))
    }
    defer conn.Close()

    localAddr  := conn.LocalAddr().(*net.UDPAddr)
    interfaces := MustIfaces()

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
            
			if ipNet.IP.Equal(localAddr.IP) {
                return iface.Name
            }
        }
    }

    utils.Abort(fmt.Sprintf("No interface found with IP %s", localAddr.IP))
	return ""
}