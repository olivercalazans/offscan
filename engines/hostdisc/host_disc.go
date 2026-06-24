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
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"offscan/internal/conv"
	"offscan/internal/generators"
	"offscan/internal/netroute"
	"offscan/internal/sniffer"
)



func Run(args []string) {
    hd := hostDiscovery{}
    hd.parseArgs(args)
    hd.execute()
}



type hostDiscovery struct {
    activeIPs    map[[4]byte]hostInfo
    ips          generators.Ipv4Iter
    iface        net.Interface
    mut          sync.Mutex
    myIP         net.IP
    protocols    protocols
    running      atomic.Bool
    sniffer     *sniffer.Sniffer
    snifferCh    <-chan []byte
    wgPktProc    sync.WaitGroup
    tools       *probeTools
}


type protocols struct {
    arp, icmp, tcp bool
}



func (hd *hostDiscovery) execute() {
    hd.displayExecInfo()
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



func (hd *hostDiscovery) resolveNames() {
    hd.mut.Lock()
    defer hd.mut.Unlock()

	for ipBytes, info := range hd.activeIPs {
        ip       := net.IP(ipBytes[:])
        name     := netroute.GetHostName(ip.String())
        info.Name = name
        
		hd.activeIPs[ipBytes] = info
    }
}



func (hd *hostDiscovery) getSortedActiveIPs() [][4]byte {
    keys := make([][4]byte, 0, len(hd.activeIPs))

    for k := range hd.activeIPs {
        keys = append(keys, k)
    }

    sort.Slice(keys, func(i, j int) bool {
        for idx := range 4 {
            if keys[i][idx] != keys[j][idx] {
                return keys[i][idx] < keys[j][idx]
            }
        }
        return false
    })
    
    return keys
}



func (hd *hostDiscovery) displayResult() {
    hd.mut.Lock()
    defer hd.mut.Unlock()

    if len(hd.activeIPs) < 1 {
        fmt.Println("No host detected")
        return
    }

    fmt.Println("")

    for _, ipBytes := range hd.getSortedActiveIPs() {
        info := hd.activeIPs[ipBytes]
        ip := net.IP(ipBytes[:])

        fmt.Printf("# %-15s  %s  %s\n", ip.String(), info.Mac.String(), info.Name)
    }
}