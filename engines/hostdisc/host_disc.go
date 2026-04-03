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

package hostdisc

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"offscan/internal/conv"
	"offscan/internal/generators"
	"offscan/internal/ifaceinfo"
	"offscan/internal/pktsniff"
	"offscan/internal/sysinfo"
)



func Run(args []string) {
    newHostDisc(args).execute()
}



type Info struct {
    Mac  net.HardwareAddr
    Name string
}



type HostDiscovery struct {
    activeIPs      map[[4]byte]Info
    delay          string
    ips           *generators.Ipv4Iter
    iface         *net.Interface
    mut            sync.Mutex
    myIP           net.IP
    icmp           bool
    tcp            bool
    udp            bool
    running        atomic.Bool
    sniffer       *pktsniff.Sniffer
    snifferCh      <-chan []byte
    wgSocks        sync.WaitGroup
    wgPktProc      sync.WaitGroup
}



func newHostDisc(argList []string) *HostDiscovery {
    args := ParseNetMapArgs(argList)

	var iface *net.Interface
	if args.Iface == nil {
		iface = sysinfo.MustDefaultInterface()
	} else {
		iface = conv.MustGetIface(*args.Iface)
	}

	cidr := ifaceinfo.MustCIDR(iface)

    return &HostDiscovery{
        activeIPs: make(map[[4]byte]Info),
        ips:       generators.NewIpv4Iter(cidr, args.Range),
        myIP:      ifaceinfo.MustIPv4(iface),
        iface:     iface,
        delay:     args.Delay,
        icmp:      args.Icmp,
        tcp:       args.Tcp,
        udp:       args.Udp,
    }
}



func (nm *HostDiscovery) execute() {
    nm.validateProtoFlags()
    nm.displayExecInfo()
    nm.startPacketProcessor()
    nm.createGoroutines()
    nm.stopPacketProcessor()
    nm.resolveNames()
    nm.displayResult()
}



func (nm *HostDiscovery) validateProtoFlags() {
    if !nm.icmp && !nm.tcp && !nm.udp {
        nm.icmp = true
        nm.tcp  = true
        nm.udp  = true
    }
}



func (nm *HostDiscovery) displayExecInfo() {
    var protocols []string
    if nm.icmp { protocols = append(protocols, "ICMP") }
    if nm.tcp  { protocols = append(protocols, "TCP") }
    if nm.udp  { protocols = append(protocols, "UDP") }
    
	proto  := strings.Join(protocols, ", ")
    first  := conv.U32ToIP(nm.ips.StartU32)
    last   := conv.U32ToIP(nm.ips.EndU32)
    length := nm.ips.EndU32 - nm.ips.StartU32 + 1

    fmt.Printf("[*] Iface..: %s\n", nm.iface.Name)
    fmt.Printf("[*] Range..: %s - %s\n", first.String(), last.String())
    fmt.Printf("[*] Len IPs: %d\n", length)
    fmt.Printf("[*] Proto..: %s\n", proto)
}



func (nm *HostDiscovery) resolveNames() {
    nm.mut.Lock()
    defer nm.mut.Unlock()

	for ipBytes, info := range nm.activeIPs {
        ip       := net.IP(ipBytes[:])
        name     := sysinfo.GetHostName(ip.String())
        info.Name = name
        
		nm.activeIPs[ipBytes] = info
    }
}



func (nm *HostDiscovery) displayResult() {
    fmt.Println("")
    fmt.Println("IP Address       MAC Address        Hostname")
    fmt.Println("---------------  -----------------  --------")

	nm.mut.Lock()
    defer nm.mut.Unlock()

	for ipBytes, info := range nm.activeIPs {
        ip := net.IP(ipBytes[:])
        fmt.Printf("%-15s  %-17s  %s\n", ip.String(), info.Mac.String(), info.Name)
    }
}