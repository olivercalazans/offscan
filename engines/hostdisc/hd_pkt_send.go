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
	"offscan/internal/pktbuild"
	"offscan/internal/sockets"
	"time"
)



const delay = 40 * time.Millisecond


type hostDiscProbes struct {
    l2sock   sockets.Layer2Socket
    l3sock   sockets.Layer3Socket
    arp     *pktbuild.ArpPacket
    icmp    *pktbuild.IcmpPacket
    tcp     *pktbuild.TcpPacket
    dstIP    net.IP
}



func (hd *hostDiscovery) sendProbes() {
    hd.initProbeTools()
    var pktErr uint16 = 0

	for {
        dstIP, hasIP := hd.ips.Next()
        
        if !hasIP { break }

        hd.tools.dstIP = dstIP

        if hd.protocols.arp {
            ok := hd.sendArpProbe()
            if !ok { pktErr++ }
        }

        if hd.protocols.icmp {
            ok := hd.sendIcmpProbe()
            if !ok { pktErr++ }
        }

        if hd.protocols.tcp {
            ok := hd.sendTcpProbe()
            if !ok { pktErr++ }
        }
    }

    hd.stopTools()
    if pktErr > 0 { fmt.Printf("[!] Packets not sent = %d\n", pktErr) }
    time.Sleep(2 * time.Second)
}



func (hd *hostDiscovery) initProbeTools() {
    hd.tools = &probeTools{}

    hd.tools.l2sock = sockets.NewL2Socket(&hd.iface)
    hd.tools.l3sock = sockets.NewL3Socket(&hd.iface)
    
    if hd.protocols.arp {
        hd.tools.arp = pktbuild.NewArpPkt()
        hd.tools.SetArpReqStatic(hd.iface.HardwareAddr, hd.myIP)
    }

    if hd.protocols.icmp {
        hd.tools.icmp = pktbuild.NewIcmpPkt()
    }

    if hd.protocols.tcp {
        hd.tools.tcp  = pktbuild.NewTcpPkt()
        hd.tools.rand = generators.NewRandomValues()
    }
}



func (hd *hostDiscovery) sendArpProbe() bool {
    hd.tools.arp.SetTargetIP(hd.tools.dstIP)
    pkt := hd.tools.arp.Pkt()
    
    hd.tools.l2sock.Send(pkt)
    time.Sleep(delay)
    
    return true
}



func (hd *hostDiscovery) sendIcmpProbe() bool {
    hd.tools.icmp.IPHdr.SetSrcIP(hd.myIP)
    hd.tools.icmp.IPHdr.SetDstIP(hd.tools.dstIP)    
    
    pkt := hd.tools.icmp.Pkt()    
    hd.tools.l3sock.SendTo(pkt, hd.tools.dstIP)
    time.Sleep(delay)
    
    return true
}



func (hd *hostDiscovery) sendTcpProbe() bool {
    hd.tools.tcp.IPHdr.SetSrcIP(hd.myIP)
    hd.tools.tcp.IPHdr.SetDstIP(hd.tools.dstIP)
    hd.tools.tcp.SetSrcPort(hd.tools.rand.RandomPort())
    hd.tools.tcp.SetDstPort(80)
    
    pkt := hd.tools.tcp.Pkt()
    hd.tools.l3sock.SendTo(pkt, hd.tools.dstIP)
    time.Sleep(delay)
    
    return true
}



func (hd *hostDiscovery) stopTools() {
    if hd.protocols.arp {
        if err := hd.tools.l2sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 2 socket: %v\n", err)
        }
    }

    if hd.protocols.icmp || hd.protocols.tcp {
        if err := hd.tools.l3sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 3 socket: %v\n", err)
        }
    }

    hd.tools = nil
}