package iface

import (
	"fmt"
	"net"
	"offscan/utils"
	"os"
	"strconv"
	"strings"
)



type Iface struct {
    net.Interface
}



func New(name string) *Iface {
    iface, err := net.InterfaceByName(name)

	if err != nil {
        utils.Abort(fmt.Sprintf("Network interface does not exist: %s", name))
    }

	return &Iface{*iface}
}



func (i *Iface) Name() string {
    return i.Interface.Name
}



func (i *Iface) Index() int {
    return i.Interface.Index
}



func (i *Iface) MAC() net.HardwareAddr {
    return i.Interface.HardwareAddr
}



func (i *Iface) IPv4() (net.IP, error) {
    addrs, err := i.Addrs()
    if err != nil {
        return nil, fmt.Errorf("Unable to get interface IPs: %w", err)
    }

    for _, addr := range addrs {
        ipNet, ok := addr.(*net.IPNet)
     
        if !ok {
            continue
        }
     
        ip := ipNet.IP
        if ip.To4() == nil {
            continue
        }
     
        return ip, nil
    }
    
    return nil, fmt.Errorf("No IPv4 address found on interface")
}



func (i *Iface) State() (string, error) {
    data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/operstate", i.Interface.Name))

	if err != nil {
        return "", err
    }

	return strings.ToUpper(strings.TrimSpace(string(data))), nil
}



func (i *Iface) IsWireless() bool {
    _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/wireless", i.Interface.Name))
    return err == nil
}



func (i *Iface) Type() string {
    if i.IsWireless() {
        return "Wireless"
    }

	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", i.Interface.Name))

	if err != nil {
        return "Unknown"
    }

	typ := strings.TrimSpace(string(data))

	switch typ {
    	case "1":   return "Ethernet"
    	case "772": return "Loopback"
    	default:    return "Type-" + typ
    }
}



func (i *Iface) CIDR() (string, error) {
    addrs, err := i.Addrs()
    
	if err != nil {
        return "", err
    }
    
	for _, addr := range addrs {
        ipnet, ok := addr.(*net.IPNet)
    
		if !ok {
            continue
        }
    
		if ipnet.IP.To4() != nil {
            return ipnet.String(), nil
        }
    }
    
	return "", fmt.Errorf("No IPv4 address found")
}



func (i *Iface) GatewayIP() (net.IP, error) {
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
        
		if fields[0] != i.Interface.Name {
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



func (i *Iface) GatewayMAC() (net.HardwareAddr, error) {
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

		if fields[5] != i.Interface.Name {
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