package ifaceinfo

import (
	"encoding/binary"
	"fmt"
	"net"
)



func BroadcastFromCIDR(cidr string) (net.IP, error) {
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, fmt.Errorf("Invalid CIDR: %w", err)
    }

	ipv4 := ip.To4()
    if ipv4 == nil {
        return nil, fmt.Errorf("CIDR is not IPv4")
    }

    ipU32 := binary.BigEndian.Uint32(ipv4)
    mask  := binary.BigEndian.Uint32(ipnet.Mask)

    broadcastU32 := ipU32 | ^mask
    broadcast    := make(net.IP, 4)
    binary.BigEndian.PutUint32(broadcast, broadcastU32)
    
	return broadcast, nil
}