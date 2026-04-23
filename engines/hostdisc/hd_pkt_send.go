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
	"offscan/internal/pktbuilder"
	"offscan/internal/sockets"
	"offscan/internal/utils"
	"time"
)



func (hd *hostDiscovery) createGoroutines() {
    if hd.protocols.arp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("arp", *hd.ips)
    }

    if hd.protocols.icmp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("icmp", *hd.ips)
    }
    
	if hd.protocols.tcp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("tcp", *hd.ips)
    }
    
	if hd.protocols.udp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("udp", *hd.ips)
    }

    hd.wgSocks.Wait()
    time.Sleep(3 * time.Second)
}



func (hd *hostDiscovery) sendProbes(proto string, ips generators.Ipv4Iter) {
    defer hd.wgSocks.Done()

	switch proto {
    case "arp":  hd.sendArpProbes()
    case "icmp": hd.sendIcmpProbes()
	case "tcp":  hd.sendTcpProbes()
	case "udp":  hd.sendUdpProbes()
	default:     utils.Abort(fmt.Sprintf("Unknown protocol: %s", proto))
    }
    
}



func (hd *hostDiscovery) sendArpProbes() {
    ips    := *hd.ips
    delays := generators.NewDelayIter(hd.delay, int(ips.Total()))
    socket := sockets.NewL3Socket(hd.iface)
    srcMAC := hd.iface.HardwareAddr
    
    pktBuild := pktbuilder.NewArpPkt()
    pktBuild.AddStaticAddrs(srcMAC, hd.myIP)
    
    for {
        dstIP, ok1 := ips.Next()
        delay, ok2 := delays.Next()
        
        if !ok1 || !ok2  {
            break
        }

        pkt := pktBuild.L3Pkt(dstIP)

        socket.SendTo(pkt, dstIP)
        time.Sleep(time.Duration(delay * float64(time.Second)))
    }
}



func (hd *hostDiscovery) sendIcmpProbes() {
    ips      := *hd.ips
    delays   := generators.NewDelayIter(hd.delay, int(ips.Total()))
    socket   := sockets.NewL3Socket(hd.iface)
    pktBuild := pktbuilder.NewIcmpPkt()
    
    for {
        dstIP, ok1 := ips.Next()
        delay, ok2 := delays.Next()
        
        if !ok1 || !ok2  {
            break
        }

        pkt := pktBuild.L3Pkt(hd.myIP, dstIP)

        socket.SendTo(pkt, dstIP)
        time.Sleep(time.Duration(delay * float64(time.Second)))
    }
}



func (hd *hostDiscovery) sendTcpProbes() {
    ips      := *hd.ips
    delays   := generators.NewDelayIter(hd.delay, int(ips.Total()))
    socket   := sockets.NewL3Socket(hd.iface)
    pktBuild := pktbuilder.NewTcpPkt()
    randGen  := generators.NewRandomValues()
    
    for {
        dstIP, ok1 := ips.Next()
        delay, ok2 := delays.Next()
        
        if !ok1 || !ok2  {
            break
        }

        srcPort := randGen.RandomPort()
        pkt     := pktBuild.L3Pkt(hd.myIP, srcPort, dstIP, 80)

        socket.SendTo(pkt, dstIP)
        time.Sleep(time.Duration(delay * float64(time.Second)))
    }
}



func (hd *hostDiscovery) sendUdpProbes() {
    ips      := *hd.ips
    delays   := generators.NewDelayIter(hd.delay, int(ips.Total()))
    socket   := sockets.NewL3Socket(hd.iface)
    pktBuild := pktbuilder.NewUdpPkt()
    randGen  := generators.NewRandomValues()
    
    for {
        dstIP, ok1 := ips.Next()
        delay, ok2 := delays.Next()
        
        if !ok1 || !ok2  {
            break
        }

        srcPort := randGen.RandomPort()
        pkt     := pktBuild.L3Pkt(hd.myIP, srcPort, dstIP, 53, []byte{})

        socket.SendTo(pkt, dstIP)
        time.Sleep(time.Duration(delay * float64(time.Second)))
    }
}