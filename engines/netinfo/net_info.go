package netinfo

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"offscan/conv"
	"offscan/ifaceinfo"
	"offscan/sysinfo"
)



func Run(args []string) {
    New(args).Execute()
}



type NetworkInfo struct {
    ifaceList   []net.Interface
    current     *net.Interface
    state       string
    ifType      string
    mac         string
    ip          string
    cidr        string
    hostLen     string
    mtu         string
    gatewayMac  string
    gatewayIP   string
    broadcast   string
}



func New(argList []string) *NetworkInfo {
	args := ParseNetInfoArgs(argList)
    var ifaceList []net.Interface

    if  args.Iface == "" {
        ifaceList = sysinfo.MustAllIfaces()
    } else {
        ifaceList = append(ifaceList, *conv.MustGetIface(args.Iface))
    }

    return &NetworkInfo{
        ifaceList: ifaceList,
    }
}



func (ni *NetworkInfo) Execute() {
    for idx, iface := range ni.ifaceList {
		ni.current = &iface
        
		ni.setState()
        ni.setType()
        ni.setMAC()
        ni.setIP()
        ni.setCIDR()
        ni.setHostLen()
        ni.setMTU()
        ni.setGatewayMAC()
        ni.setGatewayIP()
        ni.setBroadcast()
        ni.displayInfo(idx)
    }
}



func (ni *NetworkInfo) setState() {
    state, err := ifaceinfo.State(ni.current)
    
	if err != nil {
        ni.state = "Unknown"
    } else {
        ni.state = state
    }
}



func (ni *NetworkInfo) setType() {
    ni.ifType = ifaceinfo.Type(ni.current)
}



func (ni *NetworkInfo) setMAC() {
    ni.mac = ni.current.HardwareAddr.String()    
}



func (ni *NetworkInfo) setIP() {
    ip, err := ifaceinfo.IPv4(ni.current)
    
	if err != nil {
        ni.ip = "None"
    } else {
        ni.ip = ip.String()
    }
}



func (ni *NetworkInfo) setCIDR() {
    cidr, err := ifaceinfo.CIDR(ni.current)
    
	if err != nil {
        ni.cidr = "Unknown"
    } else {
        ni.cidr = cidr
    }
}



func (ni *NetworkInfo) setHostLen() {
    parts := strings.Split(ni.cidr, "/")
    
	if len(parts) < 2 {
        ni.hostLen = "None"
        return
    }

    cidrVal, err := strconv.Atoi(parts[1])
    if err != nil || cidrVal > 32 {
        ni.hostLen = "Unknown"
        return
    }

    hostBits   := 32 - cidrVal
    totalHosts := 1 << uint(hostBits)

    if cidrVal >= 31 {
        ni.hostLen = strconv.Itoa(totalHosts)
    } else {
        ni.hostLen = strconv.Itoa(totalHosts - 2)
    }
}



func (ni *NetworkInfo) setMTU() {
    ni.mtu = fmt.Sprintf("%d", ni.current.MTU)
}



func (ni *NetworkInfo) setGatewayMAC() {
    mac, err := ifaceinfo.GatewayMAC(ni.current)

    if err != nil {
        ni.gatewayMac = "Unknown"
    } else {
        ni.gatewayMac = mac.String()
    }
}



func (ni *NetworkInfo) setGatewayIP() {
    ip, err := ifaceinfo.GatewayIP(ni.current)
    
	if err != nil {
        ni.gatewayIP = "Unknown"
    } else {
        ni.gatewayIP = ip.String()
    }
}



func (ni *NetworkInfo) setBroadcast() {
    if ni.ifType == "Loopback" {
        ni.broadcast = "None"
        return
    }

	ip, err := ifaceinfo.BroadcastFromCIDR(ni.cidr)
    
	if err != nil {
        ni.broadcast = "Unknown"
    } else {
        ni.broadcast = ip.String()
    }
}



func (ni *NetworkInfo) displayInfo(index int) {
    fmt.Printf("#%d Interface: %s - State: %s\n", index, ni.current.Name, ni.state)
    fmt.Println("  - Type.......:", ni.ifType)
    fmt.Println("  - MAC........:", ni.mac)
    fmt.Println("  - IP.........:", ni.ip)
    fmt.Println("  - CIDR.......:", ni.cidr)
    fmt.Println("  - Len hosts..:", ni.hostLen)
    fmt.Println("  - MTU........:", ni.mtu)
    fmt.Println("  - Gateway MAC:", ni.gatewayMac)
    fmt.Println("  - Gateway IP.:", ni.gatewayIP)
    fmt.Println("  - Broadcast..:", ni.broadcast)
    fmt.Println()
}