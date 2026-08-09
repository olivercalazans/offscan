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
    l2sock     sockets.Layer2Socket
    l3sock     sockets.Layer3Socket
    arp       *pktbuild.ArpPacket
    icmp      *pktbuild.IcmpPacket
    tcp       *pktbuild.TcpPacket
    rand      *generators.RandomValues
    iface      net.Interface
    dstIP      net.IP
    myIP       net.IP
    protocols  protocols
}



func (hdp *hostDiscProbes) initProbeTools(
    iface      net.Interface, 
    myIP       net.IP, 
    protocols  protocols,
) {
    hdp.iface     = iface
    hdp.myIP      = myIP
    hdp.protocols = protocols
    
    hdp.initArpPkt()
    hdp.initL2Socket()
    hdp.initIcmpPkt()
    hdp.initTcpPkt()
    hdp.initL3Socket()
}



func (hdp *hostDiscProbes) initArpPkt() {
    if !hdp.protocols.arp { return }

    hdp.arp = pktbuild.NewArpPkt()
    hdp.SetArpReqStatic(hdp.iface.HardwareAddr, hdp.myIP)
}



func (hdp *hostDiscProbes) initL2Socket() {
    if !hdp.protocols.arp { return }
    hdp.l2sock = sockets.NewL2Socket(&hdp.iface)
}



func (hdp *hostDiscProbes) initIcmpPkt() {
    if !hdp.protocols.icmp { return }
    hdp.icmp = pktbuild.NewIcmpPkt()
}



func (hdp *hostDiscProbes) initTcpPkt() {
    if !hdp.protocols.tcp { return }
    hdp.tcp  = pktbuild.NewTcpPkt()
    hdp.rand = generators.NewRandomValues()
}



func (hdp *hostDiscProbes) initL3Socket() {
    if !hdp.protocols.icmp && !hdp.protocols.tcp { return }
    hdp.l3sock = sockets.NewL3Socket(&hdp.iface)
}



func (hdp *hostDiscProbes) sendArpProbe() {
    hdp.arp.SetTargetIP(hdp.dstIP)
    pkt := hdp.arp.Pkt()
    hdp.l2sock.Send(pkt)
    time.Sleep(delay)    
}



func (hdp *hostDiscProbes) SetArpReqStatic(
	srcMac  net.HardwareAddr,
	srcIP   net.IP,
) {
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hdp.arp.EtherHdr.SetDstAddr(broadcast)
	hdp.arp.EtherHdr.SetSrcAddr(srcMac)

	nullMac := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	hdp.arp.SetRequestOpcode()
	hdp.arp.SetSenderMAC(srcMac)
	hdp.arp.SetSenderIP(srcIP)
	hdp.arp.SetTargetMAC(nullMac)
}



func (hdp *hostDiscProbes) sendIcmpProbe() {
    hdp.setIcmpPkt()
    pkt := hdp.icmp.Pkt()    
    
    hdp.l3sock.SendTo(pkt, hdp.dstIP)    
    time.Sleep(delay)
}



func (hdp *hostDiscProbes) setIcmpPkt() {
    hdp.icmp.IPHdr.SetSrcIP(hdp.myIP)
    hdp.icmp.IPHdr.SetDstIP(hdp.dstIP)    
}



func (hdp *hostDiscProbes) sendTcpProbe() {
    hdp.setTcpPkt()
    pkt := hdp.tcp.Pkt()
    
    hdp.l3sock.SendTo(pkt, hdp.dstIP)    
    time.Sleep(delay)
}



func (hdp *hostDiscProbes) setTcpPkt() {
    hdp.tcp.IPHdr.SetSrcIP(hdp.myIP)
    hdp.tcp.IPHdr.SetDstIP(hdp.dstIP)
    hdp.tcp.SetSrcPort(hdp.rand.RandomPort())
    hdp.tcp.SetDstPort(80)
}



func (hdp *hostDiscProbes) stopTools() {
    if hdp.protocols.arp {
        if err := hdp.l2sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 2 socket: %v\n", err)
        }
    }

    if hdp.protocols.icmp || hdp.protocols.tcp {
        if err := hdp.l3sock.Close(); err != nil {
            fmt.Printf("[!] Error closing layer 3 socket: %v\n", err)
        }
    }
}