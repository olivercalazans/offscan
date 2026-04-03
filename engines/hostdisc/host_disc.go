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
	"offscan/internal/pktsniffer"
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
    sniffer       *pktsniffer.Sniffer
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



func (hd *HostDiscovery) execute() {
    hd.validateProtoFlags()
    hd.displayExecInfo()
    hd.startPacketProcessor()
    hd.createGoroutines()
    hd.stopPacketProcessor()
    hd.resolveNames()
    hd.displayResult()
}



func (hd *HostDiscovery) validateProtoFlags() {
    if !hd.icmp && !hd.tcp && !hd.udp {
        hd.icmp = true
        hd.tcp  = true
        hd.udp  = true
    }
}



func (hd *HostDiscovery) displayExecInfo() {
    var protocols []string
    if hd.icmp { protocols = append(protocols, "ICMP") }
    if hd.tcp  { protocols = append(protocols, "TCP") }
    if hd.udp  { protocols = append(protocols, "UDP") }
    
	proto  := strings.Join(protocols, ", ")
    first  := conv.U32ToIP(hd.ips.StartU32)
    last   := conv.U32ToIP(hd.ips.EndU32)
    length := hd.ips.EndU32 - hd.ips.StartU32 + 1

    fmt.Printf("[*] Iface..: %s\n", hd.iface.Name)
    fmt.Printf("[*] Range..: %s - %s\n", first.String(), last.String())
    fmt.Printf("[*] Len IPs: %d\n", length)
    fmt.Printf("[*] Proto..: %s\n", proto)
}



func (hd *HostDiscovery) resolveNames() {
    hd.mut.Lock()
    defer hd.mut.Unlock()

	for ipBytes, info := range hd.activeIPs {
        ip       := net.IP(ipBytes[:])
        name     := sysinfo.GetHostName(ip.String())
        info.Name = name
        
		hd.activeIPs[ipBytes] = info
    }
}



func (hd *HostDiscovery) displayResult() {
    fmt.Println("")
    fmt.Println("IP Address       MAC Address        Hostname")
    fmt.Println("---------------  -----------------  --------")

	hd.mut.Lock()
    defer hd.mut.Unlock()

	for ipBytes, info := range hd.activeIPs {
        ip := net.IP(ipBytes[:])
        fmt.Printf("%-15s  %-17s  %s\n", ip.String(), info.Mac.String(), info.Name)
    }
}