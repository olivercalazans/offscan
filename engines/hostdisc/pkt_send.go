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
	"context"
	"fmt"
	"offscan/internal/generators"
	"offscan/internal/models"
	"offscan/internal/pktbuild"
	"offscan/internal/sockets"

	"golang.org/x/time/rate"
)



func (hd *hostDiscovery) initProbeTools() {
    hd.limiter = rate.NewLimiter(rate.Limit(250), 25)

    hd.initArpPkt()
    hd.initL2Socket()
    hd.initIcmpPkt()
    hd.initTcpPkt()
    hd.initL3Socket()
}



func (hd *hostDiscovery) initArpPkt() {
    if !hd.protocols.arp { return }
    hd.arp = pktbuild.NewArpPkt()
    hd.setArpReqStatic()
}



func (hd *hostDiscovery) initL2Socket() {
    if !hd.protocols.arp { return }
    hd.l2sock = sockets.NewL2Socket(&hd.iface)
}



func (hd *hostDiscovery) initIcmpPkt() {
    if !hd.protocols.icmp { return }
    hd.icmp = pktbuild.NewIcmpPkt()
}



func (hd *hostDiscovery) initTcpPkt() {
    if !hd.protocols.tcp { return }
    hd.tcp  = pktbuild.NewTcpPkt()
    hd.rand = generators.NewRandomValues()
}



func (hd *hostDiscovery) initL3Socket() {
    if !hd.protocols.icmp && !hd.protocols.tcp { return }
    hd.l3sock = sockets.NewL3Socket(&hd.iface)
}



func (hd *hostDiscovery) sendArpProbe(ctx context.Context) error {
    if err := hd.limiter.Wait(ctx); err != nil {
        return err
    }

    hd.arp.SetTargetIP(hd.dstIP)
    pkt := hd.arp.Pkt()
    return hd.l2sock.Send(pkt)
}



func (hd *hostDiscovery) setArpReqStatic() {
    myMAC     := models.MustMacFromSlice(hd.iface.HardwareAddr)
    broadcast := models.MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	hd.arp.EtherHdr.SetDstAddr(broadcast)
	hd.arp.EtherHdr.SetSrcAddr(myMAC)

	nullMac := models.MAC{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	hd.arp.SetRequestOpcode()
	hd.arp.SetSenderMAC(myMAC)
	hd.arp.SetSenderIP(hd.myIP)
	hd.arp.SetTargetMAC(nullMac)
}



func (hd *hostDiscovery) sendIcmpProbe(ctx context.Context) error {
    if err := hd.limiter.Wait(ctx); err != nil {
        return err
    }

    hd.setIcmpPkt()
    pkt := hd.icmp.Pkt()    
    return hd.l3sock.SendTo(pkt, hd.dstIP)
}



func (hd *hostDiscovery) setIcmpPkt() {
    hd.icmp.IPHdr.SetSrcIP(hd.myIP)
    hd.icmp.IPHdr.SetDstIP(hd.dstIP)    
}



func (hd *hostDiscovery) sendTcpProbe(ctx context.Context) error {
    if err := hd.limiter.Wait(ctx); err != nil {
        return err
    }

    hd.setTcpPkt()
    pkt := hd.tcp.Pkt()
    return hd.l3sock.SendTo(pkt, hd.dstIP)
}



func (hd *hostDiscovery) setTcpPkt() {
    hd.tcp.IPHdr.SetSrcIP(hd.myIP)
    hd.tcp.IPHdr.SetDstIP(hd.dstIP)
    hd.tcp.SetSrcPort(hd.rand.RandomPort())
    hd.tcp.SetDstPort(80)
}



func (hd *hostDiscovery) stopTools() {
    if hd.protocols.arp {
        if err := hd.l2sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 2 socket: %v\n", err)
        }
    }

    if hd.protocols.icmp || hd.protocols.tcp {
        if err := hd.l3sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 3 socket: %v\n", err)
        }
    }
}