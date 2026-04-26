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


func PingPkt(srcIP, dstIP net.IP) ([]byte, error) {
	ip := &layers.IPv4{
		Version    : 4,
		IHL        : 5,
		TOS 	   : 0,
		Length	   : 0,
		Id 		   : 0x1234,
		Flags      : layers.IPv4DontFragment,
		FragOffset : 0,
		TTL		   : 64,
		Protocol   : layers.IPProtocolICMPv4,
		SrcIP      : srcIP,
		DstIP      : dstIP,
	}

	icmp := &layers.ICMPv4{
		TypeCode : layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id	     : 0x1234,
		Seq	     : 1,
	}

	buf  := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, ip, icmp)
	
	if err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}