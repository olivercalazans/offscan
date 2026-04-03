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



func (hd *HostDiscovery) createGoroutines() {
    if hd.icmp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("icmp", *hd.ips)
    }
    
	if hd.tcp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("tcp", *hd.ips)
    }
    
	if hd.udp {
        hd.wgSocks.Add(1)
        go hd.sendProbes("udp", *hd.ips)
    }

    hd.wgSocks.Wait()
    time.Sleep(3 * time.Second)
}



func (hd *HostDiscovery) sendProbes(proto string, ips generators.Ipv4Iter) {
    defer hd.wgSocks.Done()

    delays  := generators.NewDelayIter(hd.delay, int(ips.Total()))
    randGen := generators.NewRandomValues(nil, nil)
    socket  := sockets.NewL3Socket(hd.iface)

    icmpPkt := pktbuilder.NewIcmpPkt()
    tcpPkt  := pktbuilder.NewTcpPkt()
    udpPkt  := pktbuilder.NewUdpPkt()

    for {
        dstIP, ok := ips.Next()
        if !ok {
            break
        }
        
		delay, ok := delays.Next()
        if !ok {
            break
        }

        var pkt []byte
        
		switch proto {
        case "icmp":
            pkt = icmpPkt.L3Pkt(hd.myIP, dstIP)
        
		case "tcp":
            srcPort := randGen.RandomPort()
            pkt = tcpPkt.L3Pkt(hd.myIP, srcPort, dstIP, 80)
        
		case "udp":
            srcPort := randGen.RandomPort()
            pkt = udpPkt.L3Pkt(hd.myIP, srcPort, dstIP, 53, []byte{})
        
		default:
            utils.Abort(fmt.Sprintf("Unknown protocol: %s", proto))
        }

        socket.SendTo(pkt, dstIP)
        time.Sleep(time.Duration(delay * float64(time.Second)))
    }
}