package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)



func GetFirstAndLastIP(cidr string) (uint32, uint32) {
    _, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
        Abort(fmt.Sprintf("Invalid CIDR: %s", cidr))
    }

    network := binary.BigEndian.Uint32(ipnet.IP.To4())
    mask    := binary.BigEndian.Uint32(ipnet.Mask)

    broadcast := network | ^mask

    first := network + 1
    last  := broadcast - 1

    if first > last {
        Abort(fmt.Sprintf("No usable IPs in CIDR: %s", cidr))
    }

    return first, last
}