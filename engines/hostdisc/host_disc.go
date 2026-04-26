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
	"offscan/internal/netroute"
	"offscan/internal/pktsniffer"
	"offscan/internal/sysinfo"
)



func Run(args []string) {
    newHostDisc(args).execute()
}



type protocols struct {
    arp, icmp, tcp, udp bool
}


type hostInfo struct {
    Mac  net.HardwareAddr
    Name string
}



type hostDiscovery struct {
    activeIPs   map[[4]byte]hostInfo
    delay       string
    ips        *generators.Ipv4Iter
    iface      *net.Interface
    mut         sync.Mutex
    myIP        net.IP
    protocols   protocols
    running     atomic.Bool
    sniffer    *pktsniffer.Sniffer
    snifferCh   <-chan []byte
    wgSocks     sync.WaitGroup
    wgPktProc   sync.WaitGroup
}



func newHostDisc(argList []string) *hostDiscovery {
    var args *hostDiscArgs = ParseNetMapArgs(argList)

	var iface *net.Interface
	if args.Iface == nil {
		iface = sysinfo.MustDefaultInterface()
	} else {
		iface = conv.MustStrToIface(*args.Iface)
	}

	cidr := ifaceinfo.MustCIDR(iface)

    return &hostDiscovery{
        activeIPs: make(map[[4]byte]hostInfo),
        ips:       generators.NewIpv4Iter(cidr, args.Range),
        myIP:      ifaceinfo.MustIPv4(iface),
        iface:     iface,
        delay:     args.Delay,
        protocols: protoFlags(args, iface),
    }
}



func protoFlags(args *hostDiscArgs, iface *net.Interface) protocols {
    isLocal := true

    if args.Range != nil {
        for _, ip := range strings.Split(*args.Range, "*") {
            ipv4    := conv.MustStrToIPv4(ip)
            isLocal  = isLocal && netroute.IsLocal(iface, ipv4)
        }
    }

    prots := protocols{
        arp:  isLocal,
        icmp: args.Icmp,
        tcp:  args.Tcp,
    }

    if !prots.arp && !prots.icmp && !prots.tcp && !prots.udp{
        prots.icmp = true
        prots.tcp  = true
        prots.udp  = true
    }

    return prots
}



func (hd *hostDiscovery) execute() {
    hd.displayExecInfo()
    hd.startPacketProcessor()
    hd.createGoroutines()
    hd.stopPacketProcessor()
    hd.resolveNames()
    hd.displayResult()
}



func (hd *hostDiscovery) displayExecInfo() {
    var protoc []string
    if hd.protocols.arp  { protoc = append(protoc, "ARP") }
    if hd.protocols.icmp { protoc = append(protoc, "ICMP") }
    if hd.protocols.tcp  { protoc = append(protoc, "TCP") }
    if hd.protocols.udp  { protoc = append(protoc, "UDP") }
    
	proto  := strings.Join(protoc, ", ")
    first  := conv.U32ToIP(hd.ips.StartU32)
    last   := conv.U32ToIP(hd.ips.EndU32)
    length := hd.ips.EndU32 - hd.ips.StartU32 + 1

    fmt.Printf("[*] Iface..: %s\n", hd.iface.Name)
    fmt.Printf("[*] Range..: %s - %s\n", first.String(), last.String())
    fmt.Printf("[*] Len IPs: %d\n", length)
    fmt.Printf("[*] Proto..: %s\n", proto)
}



func (hd *hostDiscovery) resolveNames() {
    hd.mut.Lock()
    defer hd.mut.Unlock()

	for ipBytes, info := range hd.activeIPs {
        ip       := net.IP(ipBytes[:])
        name     := sysinfo.GetHostName(ip.String())
        info.Name = name
        
		hd.activeIPs[ipBytes] = info
    }
}



func (hd *hostDiscovery) displayResult() {
	hd.mut.Lock()
    defer hd.mut.Unlock()

    if len(hd.activeIPs) < 1 {
        fmt.Println("No host detected")
        return
    }

    fmt.Println("")

	for ipBytes, info := range hd.activeIPs {
        ip := net.IP(ipBytes[:])
        
        fmt.Printf("# %-15s %s (%s)", ip.String(), info.Mac.String(), info.Name)
        
        fmt.Println("")
    }
}