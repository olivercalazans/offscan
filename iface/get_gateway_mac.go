package iface

import (
	"fmt"
	"net"
	"os"
	"strings"
)



func GatewayMAC(iface *net.Interface) (net.HardwareAddr, error) {
    data, err := os.ReadFile("/proc/net/arp")

	if err != nil {
        return nil, err
    }

	lines := strings.Split(string(data), "\n")
    for _, line := range lines[1:] {
        fields := strings.Fields(line)

		if len(fields) < 6 {
            continue
        }

		if fields[5] != iface.Name {
            continue
        }

		macStr := fields[3]
        if macStr == "00:00:00:00:00:00" {
            continue
        }

		mac, err := net.ParseMAC(macStr)
        if err != nil {
            continue
        }

		return mac, nil
    }

	return nil, fmt.Errorf("Gateway MAC not found")
}