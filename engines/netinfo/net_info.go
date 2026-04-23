/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

package netinfo

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"offscan/internal/conv"
	"offscan/internal/ifaceinfo"
	"offscan/internal/sysinfo"
)



func Run(args []string) {
    newNetInfo(args).execute()
}



type networkInfo struct {
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



func newNetInfo(argList []string) *networkInfo {
	args := ParseNetInfoArgs(argList)
    var ifaceList []net.Interface

    if  args.Iface == "" {
        ifaceList = sysinfo.MustAllIfaces()
    } else {
        ifaceList = append(ifaceList, *conv.MustGetIface(args.Iface))
    }

    return &networkInfo{
        ifaceList: ifaceList,
    }
}



func (ni *networkInfo) execute() {
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



func (ni *networkInfo) setState() {
    state, err := ifaceinfo.State(ni.current)
    
	if err != nil {
        ni.state = "Unknown"
    } else {
        ni.state = state
    }
}



func (ni *networkInfo) setType() {
    ni.ifType = ifaceinfo.Type(ni.current)
}



func (ni *networkInfo) setMAC() {
    ni.mac = ni.current.HardwareAddr.String()    
}



func (ni *networkInfo) setIP() {
    ip, err := ifaceinfo.IPv4(ni.current)
    
	if err != nil {
        ni.ip = "None"
    } else {
        ni.ip = ip.String()
    }
}



func (ni *networkInfo) setCIDR() {
    cidr, err := ifaceinfo.CIDR(ni.current)
    
	if err != nil {
        ni.cidr = "Unknown"
    } else {
        ni.cidr = cidr
    }
}



func (ni *networkInfo) setHostLen() {
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



func (ni *networkInfo) setMTU() {
    ni.mtu = fmt.Sprintf("%d", ni.current.MTU)
}



func (ni *networkInfo) setGatewayMAC() {
    mac, err := ifaceinfo.GatewayMAC(ni.current)

    if err != nil {
        ni.gatewayMac = "Unknown"
    } else {
        ni.gatewayMac = mac.String()
    }
}



func (ni *networkInfo) setGatewayIP() {
    ip, err := ifaceinfo.GatewayIP(ni.current)
    
	if err != nil {
        ni.gatewayIP = "Unknown"
    } else {
        ni.gatewayIP = ip.String()
    }
}



func (ni *networkInfo) setBroadcast() {
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



func (ni *networkInfo) displayInfo(index int) {
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