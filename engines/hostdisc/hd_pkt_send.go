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
	"offscan/internal/generators"
	"offscan/internal/packet/builder"
	"time"
)



const delay = 30 * time.Millisecond



func (hd *hostDiscovery) sendProbes() {
    randGen := generators.NewRandomValues()
    hd.initPkts()
    
    var pktErr uint16 = 0

	for {
        dstIP, hasIP := hd.ips.Next()
        
        if !hasIP { break }

        if hd.protocols.arp {
            ok := hd.sendArpProbe(dstIP)
            if !ok { pktErr++ }
        }

        if hd.protocols.icmp {
            ok := hd.sendIcmpProbe(dstIP)
            if !ok { pktErr++ }
        }

        if hd.protocols.tcp {
            ok := hd.sendTcpProbe(dstIP, randGen.RandomPort())
            if !ok { pktErr++ }
        }
    }

    hd.stopSocket()
    fmt.Printf("[!] Packets not sent: %d\n", pktErr)
    time.Sleep(2 * time.Second)
}



func (hd *hostDiscovery) initPkts() {
    hd.pkts = &packets{}
    
    if hd.protocols.arp {
        hd.pkts.arp = builder.NewArpPkt()
        hd.pkts.arp.AddStaticAddrs(hd.iface.HardwareAddr, hd.myIP)
    }

    if hd.protocols.icmp {
        hd.pkts.icmp = builder.NewIcmpPkt()
    }

    if hd.protocols.tcp {
        hd.pkts.tcp = builder.NewTcpPkt()
    }
}



func (hd *hostDiscovery) sendArpProbe(dstIP net.IP) bool {
    pkt := hd.pkts.arp.L3RequestPkt(dstIP)
    hd.socket.SendTo(pkt, dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) sendIcmpProbe(dstIP net.IP) bool {
    pkt := hd.pkts.icmp.L3PingPkt(hd.myIP, dstIP)    
    hd.socket.SendTo(pkt, dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) sendTcpProbe(dstIP net.IP, srcPort uint16) bool {
    pkt := hd.pkts.tcp.L3SynPkt(hd.myIP, srcPort, dstIP, 80)
    hd.socket.SendTo(pkt, dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) stopSocket() {
    if hd.socket == nil { return }
    
    if err := hd.socket.Close(); err != nil {
        fmt.Printf("[!] Error closing socket: %v\n", err)
    }
}