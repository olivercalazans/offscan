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
        go hd.sendProbes("arp")
    }

    if hd.protocols.icmp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("icmp")
    }
    
	if hd.protocols.tcp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("tcp")
    }
    
	if hd.protocols.udp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("udp")
    }

    hd.wgSocks.Wait()
    time.Sleep(3 * time.Second)
}



func (hd *hostDiscovery) sendProbes(proto string) {
    defer hd.wgSocks.Done()

	switch proto {
    case "arp":  hd.sendArpProbes()
    case "icmp": hd.sendIcmpProbes()
	case "tcp":  hd.sendTcpProbes()
	default:     utils.Abort(fmt.Sprintf("Unknown protocol: %s", proto))
    }
    
}



func (hd *hostDiscovery) sendArpProbes() {
    ips    := *hd.ips
    delays := generators.NewDelayIter(hd.delay, int(ips.Total()))
    socket := sockets.NewL3Socket(hd.iface)
    srcMAC := hd.iface.HardwareAddr
        
    for {
        dstIP, ok1 := ips.Next()
        delay, ok2 := delays.Next()
        
        if !ok1 || !ok2  {
            break
        }

        if pkt, err := pktbuilder.ArpRequest(srcMAC, hd.myIP, dstIP); err == nil {
            socket.SendTo(pkt, dstIP)
            time.Sleep(time.Duration(delay * float64(time.Second)))
        }
    }
}



func (hd *hostDiscovery) sendIcmpProbes() {
    ips    := *hd.ips
    delays := generators.NewDelayIter(hd.delay, int(ips.Total()))
    socket := sockets.NewL3Socket(hd.iface)
    
    for {
        dstIP, ok1 := ips.Next()
        delay, ok2 := delays.Next()
        
        if !ok1 || !ok2  {
            break
        }

        if pkt, err := pktbuilder.PingPkt(hd.myIP, dstIP); err == nil {
            socket.SendTo(pkt, dstIP)
            time.Sleep(time.Duration(delay * float64(time.Second)))
        }
    }
}



func (hd *hostDiscovery) sendTcpProbes() {
    ips     := *hd.ips
    delays  := generators.NewDelayIter(hd.delay, int(ips.Total()))
    socket  := sockets.NewL3Socket(hd.iface)
    randGen := generators.NewRandomValues()
    
    for {
        dstIP, ok1 := ips.Next()
        delay, ok2 := delays.Next()
        
        if !ok1 || !ok2  {
            break
        }

        srcPort := randGen.RandomPort()
        
        if pkt, err := pktbuilder.TcpSynPkt(hd.myIP, dstIP, srcPort, 80); err == nil {
            socket.SendTo(pkt, dstIP)
            time.Sleep(time.Duration(delay * float64(time.Second)))
        }
    }
}