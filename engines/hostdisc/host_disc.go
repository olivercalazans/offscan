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
	"math/bits"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"offscan/internal/conv"
	"offscan/internal/generators"
	"offscan/internal/netroute"
	"offscan/internal/pktdissec"
	"offscan/internal/sniffer"
)



func Run(args []string) {
    hd := hostDiscovery{}
    hd.parseArgs(args)
    hd.execute()
}



type hostDiscovery struct {
    activeIPs   map[hostInfo]string
    dissector   pktdissec.PacketDissector
    ips         generators.Ipv4Iter
    iface       net.Interface
    myIP        net.IP
    protocols   protocols
    running     atomic.Bool
    sniffer     sniffer.Sniffer
    snifferCh   <-chan []byte
    wgPktProc   sync.WaitGroup
}


type protocols struct {
    arp, icmp, tcp bool
}



func (hd *hostDiscovery) execute() {
    hd.displayExecInfo()
    hd.startSniffer()
    hd.startPacketProcessor()
    hd.sendProbes()
    hd.stopPacketProcessor()
    hd.resolveNames()
    hd.displayResult()
}



func (hd *hostDiscovery) displayExecInfo() {
    var protoc []string
    if hd.protocols.arp  { protoc = append(protoc, "ARP") }
    if hd.protocols.icmp { protoc = append(protoc, "ICMP") }
    if hd.protocols.tcp  { protoc = append(protoc, "TCP") }
    
	proto  := strings.Join(protoc, ", ")
    first  := conv.U32ToIP(hd.ips.StartU32)
    last   := conv.U32ToIP(hd.ips.EndU32)
    length := hd.ips.EndU32 - hd.ips.StartU32 + 1

    fmt.Printf("[i] Iface..: %s\n", hd.iface.Name)
    fmt.Printf("[i] Range..: %s - %s\n", first.String(), last.String())
    fmt.Printf("[i] Len IPs: %d\n", length)
    fmt.Printf("[i] Proto..: %s\n", proto)
}



func (hd *hostDiscovery) startSniffer() {
    hd.sniffer   = *sniffer.NewSniffer(hd.iface, hd.getBpfFilter(), false)
    hd.snifferCh = hd.sniffer.Start()
}



func (hd *hostDiscovery) getBpfFilter() string {
    return fmt.Sprintf(
        "(dst host %s and src net %s) or (arp[6:2] = 2)", 
        hd.myIP.String(),
        hd.cidrForBPFFilter(),
    )
}



func (hd *hostDiscovery) cidrForBPFFilter() string {
    xor := hd.ips.StartU32 ^ hd.ips.EndU32
    var leadingZeros int
    
	if xor == 0 {
        leadingZeros = 32
    } else {
        leadingZeros = bits.LeadingZeros32(xor)
	}
    
	prefixLen := uint8(leadingZeros)
    var mask uint32
    
	if prefixLen == 0 {
        mask = 0
    } else {
        mask = ^uint32(0) << (32 - prefixLen)
    }
    
	networkAddr := hd.ips.StartU32 & mask
    ip 			:= conv.U32ToIP(networkAddr)
    
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen)
}



func (hd *hostDiscovery) sendProbes() {
    hdp := hostDiscProbes{}
    hdp.initProbeTools(hd.iface, hd.myIP, hd.protocols)

	for {
        dstIP, hasIP := hd.ips.Next()
        
        if !hasIP { break }

        hdp.dstIP = dstIP

        if hd.protocols.arp  { hdp.sendArpProbe()  }
        if hd.protocols.icmp { hdp.sendIcmpProbe() }
        if hd.protocols.tcp  { hdp.sendTcpProbe()  }
    }

    hdp.stopTools()
    time.Sleep(2 * time.Second)
}



func (hd *hostDiscovery) resolveNames() {
	for addrs := range hd.activeIPs {
        ip   := net.IP(addrs.ip[:])
        name := netroute.GetHostName(ip.String())        
		
        hd.activeIPs[addrs] = name
    }
}



func (hd *hostDiscovery) displayResult() {
	if len(hd.activeIPs) < 1 {
		fmt.Println("No host detected")
		return
	}

	fmt.Println("")

	for _, info := range hd.getSortedActiveIPs() {
		hostname := hd.activeIPs[info]

		ip  := net.IP(info.ip[:])
		mac := net.HardwareAddr(info.mac[:])

		fmt.Printf("# %-15s  %s  %s\n", ip.String(), mac.String(), hostname)
	}
}




func (hd *hostDiscovery) getSortedActiveIPs() []hostInfo {
	keys := make([]hostInfo, 0, len(hd.activeIPs))

	for k := range hd.activeIPs {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		for idx := 0; idx < 4; idx++ {
			if keys[i].ip[idx] != keys[j].ip[idx] {
				return keys[i].ip[idx] < keys[j].ip[idx]
			}
		}
		return false
	})

	return keys
}