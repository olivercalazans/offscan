package sysinfo

import (
	"net"
	"offscan/utils"
)



func SrcIPFromDstIP(dstIP net.IP) net.IP {
    dst := dstIP.String() + ":53"

    conn, err := net.Dial("udp", dst)
    if err != nil {
        utils.Abort("Failed to connect UDP socket: " + err.Error())
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    ip := localAddr.IP

    if ip.To4() == nil {
        utils.Abort("Expected a local IPv4 address, but got IPv6")
    }

    return ip
}