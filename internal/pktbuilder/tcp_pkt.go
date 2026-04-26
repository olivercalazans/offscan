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

package pktbuilder

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)



func TcpSynPkt(srcIP, dstIP net.IP, srcPort, dstPort uint16) ([]byte, error) {
	ip := &layers.IPv4{
		Version  : 4,
		IHL      : 5,
		TOS      : 0,
		Id       : 0x1234,
		Flags    : layers.IPv4DontFragment,
		TTL      : 64,
		Protocol : layers.IPProtocolTCP,
		SrcIP    : srcIP,
		DstIP    : dstIP,
	}

	tcp := &layers.TCP{
		SrcPort : layers.TCPPort(srcPort),
		DstPort : layers.TCPPort(dstPort),
		Seq     : 1,
		Ack     : 0,
		SYN     : true,
		ACK     : false,
		Window  : 64240,
		Options : nil,
	}

    tcp.SetNetworkLayerForChecksum(ip)

	buf  := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	
    if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		return nil, err
	}
	
    return buf.Bytes(), nil
}