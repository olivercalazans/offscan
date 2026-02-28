package iface

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)



func GatewayIP(iface *net.Interface) (net.IP, error) {
    data, err := os.ReadFile("/proc/net/route")
    
	if err != nil {
        return nil, err
    }
    
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
        fields := strings.Fields(line)
        
		if len(fields) < 4 {
            continue
        }
        
		if fields[0] != iface.Name {
            continue
        }

		gateHex := fields[2]
        if gateHex == "00000000" {
            continue
        }

		ip, err := hexToIP(gateHex)
        if err != nil {
            continue
        }

		return ip, nil
    }

	return nil, fmt.Errorf("Gateway not found")
}



func hexToIP(hex string) (net.IP, error) {
    if len(hex) != 8 {
        return nil, fmt.Errorf("Invalid hex length")
    }

	b := make([]byte, 4)
    for i := 0; i < 4; i++ {
        val, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)

		if err != nil {
            return nil, err
        }
        b[3-i] = byte(val)
    }

	return net.IPv4(b[0], b[1], b[2], b[3]), nil
}