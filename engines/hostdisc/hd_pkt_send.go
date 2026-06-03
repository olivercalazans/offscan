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

    hd.stopSocket(&tools.socket)
    fmt.Printf("[!] Packets not sent: %d\n", pktErr)
    time.Sleep(2 * time.Second)
}



func (hd *hostDiscovery) initTools(tools *probeTools) {
    tools.socket = sockets.NewL3Socket(&hd.iface)
    
    if hd.protocols.arp {
        tools.arp = builder.NewArpPkt()
        tools.arp.AddStaticAddrs(hd.iface.HardwareAddr, hd.myIP)
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
    pkt := tools.arp.L3RequestPkt(tools.dstIP)
    tools.socket.SendTo(pkt, tools.dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) sendIcmpProbe(tools *probeTools) bool {
    pkt := tools.icmp.L3PingPkt(hd.myIP, tools.dstIP)    
    tools.socket.SendTo(pkt, tools.dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) sendTcpProbe(tools *probeTools, srcPort  uint16) bool {
    pkt := tools.tcp.L3SynPkt(hd.myIP, srcPort, tools.dstIP, 80)
    tools.socket.SendTo(pkt, tools.dstIP)
    time.Sleep(delay)
    return true
}



func (hd *hostDiscovery) stopSocket(socket *sockets.Layer3Socket) {
    if err := socket.Close(); err != nil {
        fmt.Printf("[!] Error closing socket: %v\n", err)
    }
}