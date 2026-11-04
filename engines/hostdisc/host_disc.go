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
	"sync/atomic"
	"time"

	"offscan/internal/generators"
	"offscan/internal/models"
	"offscan/internal/netroute"
	"offscan/internal/pktbuild"
	"offscan/internal/pktdissec"
	"offscan/internal/sniffer"
	"offscan/internal/sockets"
	"offscan/internal/utils"

	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)



func Run(args []string) {
    hd := hostDiscovery{}
    hd.parseArgs(args)
    hd.execute()
}


// alignment: 8 bytes
type hostDiscovery struct {
    activeIPs   models.Set[hostInfo]       //   8 bytes
    sniffer     sniffer.Sniffer            // 168 bytes
    iface       net.Interface              //  64 bytes
    dissector   pktdissec.PacketDissector  //  40 bytes
	arp        *pktbuild.ArpPacket         //   8 bytes
    icmp       *pktbuild.IcmpPacket        //   8 bytes
    tcp        *pktbuild.TcpPacket         //   8 bytes
    rand       *generators.RandomValues    //   8 bytes
	l2sock      sockets.Layer2Socket       //  56 bytes
    l3sock      sockets.Layer3Socket       //   8 bytes
	limiter    *rate.Limiter               //   8 bytes

    ips         generators.Ipv4Iter  // 24 bytes
    myIP        models.IPv4          //  4 bytes
	dstIP       models.IPv4          //  4 bytes
	sendErrors  atomic.Uint64        //  8 bytes
	lastPkt     atomic.Int64         //  8 bytes
    protocols   protocols            //  3 bytes (3x bool)
    // padding: 5 byte
}


// alignment: 1 byte
type protocols struct {
    arp  bool // 1 byte
    icmp bool // 1 byte
    tcp  bool // 1 byte
}



func (hd *hostDiscovery) execute() {
    hd.displayExecInfo()
    hd.startPacketProcessor()
    hd.sendProbes()
    hd.stopPacketProcessor()
    hd.displayResult()
}



func (hd *hostDiscovery) displayExecInfo() {
    var protoc []string
    if hd.protocols.arp  { protoc = append(protoc, "ARP")  }
    if hd.protocols.icmp { protoc = append(protoc, "ICMP") }
    if hd.protocols.tcp  { protoc = append(protoc, "TCP")  }
    
	proto  := strings.Join(protoc, ", ")
    first  := models.Uint32ToIPv4(hd.ips.StartU32)
    last   := models.Uint32ToIPv4(hd.ips.EndU32)
    length := hd.ips.EndU32 - hd.ips.StartU32 + 1

    fmt.Printf("[i] Iface..: %s\n", hd.iface.Name)
    fmt.Printf("[i] Range..: %s - %s\n", first.String(), last.String())
    fmt.Printf("[i] Len IPs: %d\n", length)
    fmt.Printf("[i] Proto..: %s\n", proto)
}



func (hd *hostDiscovery) getBpfFilter() []unix.SockFilter {
	myIP          := hd.myIP.Uint32()
	mask, netAddr := cidrMaskAndNetwork(hd.ips.StartU32, hd.ips.EndU32)

	return []unix.SockFilter{
		// 0: load EtherType
		sniffer.LDH(12),
		// 1: not IPv4 -> jump to ARP/RARP branch (idx 7)
		sniffer.JEQ(0x0800, 0, 5),

		// 2-3: IPv4 dst == myIP? otherwise reject (idx 22)
		sniffer.LDW(30),
		sniffer.JEQ(myIP, 0, 18),

		// 4-6: IPv4 src in network?
		sniffer.LDW(26),
		sniffer.AND(mask),
		sniffer.JEQ(netAddr, 14, 15), // match -> accept (21); otherwise reject (22)

		// 7-9: ARP and target protocol address == myIP?
		sniffer.JEQ(0x0806, 0, 7),
		sniffer.LDW(38),
		sniffer.JEQ(myIP, 0, 3),

		// 10-12: ARP sender protocol address in network?
		sniffer.LDW(28),
		sniffer.AND(mask),
		sniffer.JEQ(netAddr, 8, 0), // match -> accept (21)

		// 13-14: arp[6:2] == 2 (ARP reply)
		sniffer.LDH(20),
		sniffer.JEQ(2, 6, 7), // reply -> accept (21); otherwise reject (22)

		// 15-17: RARP and target protocol address == myIP?
		sniffer.JEQ(0x8035, 0, 6),
		sniffer.LDW(38),
		sniffer.JEQ(myIP, 0, 4),

		// 18-20: RARP sender protocol address in network?
		sniffer.LDW(28),
		sniffer.AND(mask),
		sniffer.JEQ(netAddr, 0, 1), // match -> accept (21); otherwise reject (22)

		sniffer.RET(sniffer.BPFAcceptAll),  // 21: accept
		sniffer.RET(0),                     // 22: reject
	}
}



func cidrMaskAndNetwork(start, end uint32) (mask, network uint32) {
	xor       := start ^ end
	prefixLen := uint8(32)

	if xor       != 0 { prefixLen = uint8(bits.LeadingZeros32(xor)) }
	if prefixLen != 0 { mask      = ^uint32(0) << (32 - prefixLen)  }
	
    network = start & mask
	return
}



func (hd *hostDiscovery) sendProbes() {
    hd.initProbeTools()
    defer hd.stopTools()

	ctx := utils.SignalContext()

    for {
        select {
        case <-ctx.Done():
            return
        default:
        }

        dstIP, hasIP := hd.ips.Next()
        if !hasIP { break }
		
        hd.dstIP = dstIP

        if hd.protocols.arp  {
            if err := hd.sendArpProbe(ctx); err != nil {
                hd.sendErrors.Add(1)
            }
        }
        
		if hd.protocols.icmp {
            if err := hd.sendIcmpProbe(ctx); err != nil {
                hd.sendErrors.Add(1)
            }
        }

        if hd.protocols.tcp  {
            if err := hd.sendTcpProbe(ctx); err != nil {
                hd.sendErrors.Add(1)
            }
        }
    }

	hd.waitForResponses(ctx, 5 * time.Second, 1 * time.Second)
}



func (hd *hostDiscovery) displayResult() {
    hosts := hd.resolveNames()

	if len(hosts) < 1 {
		fmt.Println("No host detected")
		return
	}

	fmt.Println("")

	for _, info := range hd.getSortedActiveIPs() {
		hostname := hosts[info]
		fmt.Printf("# %-15s  %s  %s\n", info.ip.String(), info.mac.String(), hostname)
	}
}



func (hd *hostDiscovery) resolveNames() map[hostInfo]string {
    hosts:= make(map[hostInfo]string, len(hd.activeIPs))

	for addrs := range hd.activeIPs {
        name         := netroute.GetHostName(addrs.ip)        		
        hosts[addrs]  = name
    }

    return hosts
}



func (hd *hostDiscovery) getSortedActiveIPs() []hostInfo {
	keys := make([]hostInfo, 0, len(hd.activeIPs))

	for k := range hd.activeIPs {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		for idx := range 4 {
			if keys[i].ip[idx] != keys[j].ip[idx] {
				return keys[i].ip[idx] < keys[j].ip[idx]
			}
		}
		return false
	})

    hd.activeIPs = nil
	return keys
}