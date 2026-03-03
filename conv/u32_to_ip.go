package conv

import "net"



func U32ToIP(n uint32) net.IP {
    return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}