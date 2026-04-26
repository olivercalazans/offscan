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



func ArpRequest(srcMac net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet, // 0x0001
		Protocol:          layers.EthernetTypeIPv4, // 0x0800
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,       // 0x0001
		SourceHwAddress:   srcMac,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}

	buf  := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, arp); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}