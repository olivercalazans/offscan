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
	"offscan/internal/pktbuilder"
	"offscan/internal/sockets"
	"time"
)



func (hd *hostDiscovery) sendProbes() {
    delays  := generators.NewDelayIter(hd.delay, int(hd.ips.Total()))
    socket  := sockets.NewL3Socket(hd.iface)
    srcMAC  := hd.iface.HardwareAddr
    randGen := generators.NewRandomValues()
    
    var pktErr uint16 = 0

	for {
        dstIP, hasIP    := hd.ips.Next()
        delay, hasDelay := delays.Next()
        
        if !hasIP || !hasDelay  {
            break
        }

        if hd.protocols.arp {
            ok := hd.sendArpProbe(socket, dstIP, srcMAC)
            if !ok { pktErr++ }
        }

        if hd.protocols.icmp {
            ok := hd.sendIcmpProbe(socket, dstIP)
            if !ok { pktErr++ }
        }

        if hd.protocols.tcp {
            ok := hd.sendTcpProbe(socket, dstIP, randGen.RandomPort())
            if !ok { pktErr++ }
        }

        time.Sleep(time.Duration(delay * float64(time.Second)))
    }

    fmt.Printf("[!] Packets not sent: %d\n", pktErr)
    time.Sleep(2 * time.Second)
}



func (hd *hostDiscovery) sendArpProbe(
    socket  *sockets.Layer3Socket,
    dstIP    net.IP,
    srcMAC   net.HardwareAddr,

) bool {

    pkt, err := pktbuilder.ArpRequest(srcMAC, hd.myIP, dstIP)

    if err != nil {
        return false
    }
    
    socket.SendTo(pkt, dstIP)
    time.Sleep(50 * time.Millisecond)
    return true
}



func (hd *hostDiscovery) sendIcmpProbe(
    socket  *sockets.Layer3Socket,
    dstIP    net.IP,

) bool {

    pkt, err := pktbuilder.PingPkt(hd.myIP, dstIP)
    
    if err != nil {
        return false
    }
    
    socket.SendTo(pkt, dstIP)
    time.Sleep(50 * time.Millisecond)
    return true
}



func (hd *hostDiscovery) sendTcpProbe(
    socket  *sockets.Layer3Socket,
    dstIP    net.IP,
    srcPort  uint16,

) bool {
    
    pkt, err := pktbuilder.TcpSynPkt(hd.myIP, dstIP, srcPort, 80)

    if err != nil {
        return false
    }

    socket.SendTo(pkt, dstIP)
    time.Sleep(50 * time.Millisecond)
    return true
}