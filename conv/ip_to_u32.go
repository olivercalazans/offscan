package conv

import (
	"encoding/binary"
	"net"
)



func IPToU32(ip net.IP) uint32 {
    ipv4 := ip.To4()
    
	if ipv4 == nil {
        return 0
    }
    
	return binary.BigEndian.Uint32(ipv4)
}