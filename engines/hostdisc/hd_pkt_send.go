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
	"offscan/internal/generators"
	"offscan/internal/packet/builder"
	"offscan/internal/sockets"
	"time"
)



const delay = 40 * time.Millisecond



func (hd *hostDiscovery) sendProbes() {
    tools   := probeTools{} 
    randGen := generators.NewRandomValues()

    hd.initTools(&tools)
    
    var pktErr uint16 = 0

	for {
        dstIP, hasIP := hd.ips.Next()
        
        if !hasIP { break }

        tools.dstIP = dstIP

        if hd.protocols.arp {
            ok := hd.sendArpProbe(&tools)
            if !ok { pktErr++ }
        }

        if hd.protocols.icmp {
            ok := hd.sendIcmpProbe(&tools)
            if !ok { pktErr++ }
        }

        if hd.protocols.tcp {
            ok := hd.sendTcpProbe(&tools, randGen.RandomPort())
            if !ok { pktErr++ }
        }
    }

    hd.stopSockets(&tools)
    fmt.Printf("[!] Packets not sent: %d\n", pktErr)
    time.Sleep(2 * time.Second)
}



func (hd *hostDiscovery) initTools(tools *probeTools) {
    tools.l2sock = sockets.NewL2Socket(&hd.iface)
    tools.l3sock = sockets.NewL3Socket(&hd.iface)
    
    if hd.protocols.arp {
        tools.arp = builder.NewArpPkt()
        tools.arp.SetRequestStatic(hd.iface.HardwareAddr, hd.myIP)
    }

    if hd.protocols.icmp {
        tools.icmp = builder.NewIcmpPkt()
        tools.icmp.Init()
    }

    if hd.protocols.tcp {
        tools.tcp = builder.NewTcpPkt()
        tools.tcp.Init()
    }
}



func (hd *hostDiscovery) sendArpProbe(tools *probeTools) bool {
    pkt := tools.arp.RequestPkt(tools.dstIP)
    tools.l2sock.Send(pkt)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) sendIcmpProbe(tools *probeTools) bool {
    pkt := tools.icmp.L3PingPkt(hd.myIP, tools.dstIP)    
    tools.l3sock.SendTo(pkt, tools.dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) sendTcpProbe(tools *probeTools, srcPort  uint16) bool {
    pkt := tools.tcp.L3SynPkt(hd.myIP, srcPort, tools.dstIP, 80)
    tools.l3sock.SendTo(pkt, tools.dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) stopSockets(tools *probeTools) {
    if hd.protocols.arp {
        if err := tools.l2sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 2 socket: %v\n", err)
        }
    }

    if hd.protocols.icmp || hd.protocols.tcp {
        if err := tools.l3sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 3 socket: %v\n", err)
        }
    }
}