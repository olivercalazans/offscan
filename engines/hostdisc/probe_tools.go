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
	"net"
	"offscan/internal/generators"
	"offscan/internal/packet/builder"
	"offscan/internal/sockets"
)


type probeTools struct {
    l2sock   sockets.Layer2Socket
    l3sock   sockets.Layer3Socket
    arp     *builder.ArpPacket
    icmp    *builder.IcmpPacket
    tcp     *builder.TcpPacket
    rand    *generators.RandomValues
    dstIP    net.IP
}



func (pt *probeTools) SetArpReqStatic(
	srcMac  net.HardwareAddr,
	srcIP   net.IP,
) {
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	pt.arp.EtherHdr.SetType(0x806)
	pt.arp.EtherHdr.SetDstAddr(broadcast)
	pt.arp.EtherHdr.SetSrcAddr(srcMac)

	nullMac := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pt.arp.SetOpcode(builder.ArpReqCode)
	pt.arp.SetSenderMAC(srcMac)
	pt.arp.SetSenderIP(srcIP)
	pt.arp.SetTargetMAC(nullMac)
}