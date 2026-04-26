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

package pktdissector

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)


type PacketDissector struct {
    pkt  []byte

    eth  layers.Ethernet
	arp  layers.ARP
	ipv4 layers.IPv4
	tcp  layers.TCP
	udp  layers.UDP

	parser        *gopacket.DecodingLayerParser
	decodedLayers []gopacket.LayerType

	isARPReply bool
}



func NewPacketDissector() *PacketDissector {
	pd := &PacketDissector{
		decodedLayers: []gopacket.LayerType{},
	}

    pd.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&pd.eth, &pd.arp, &pd.ipv4, &pd.tcp, &pd.udp,
	)

    pd.parser.IgnoreUnsupported = true

	return pd
}



func (pd *PacketDissector) UpdatePkt(rawPkt []byte) {
	pd.pkt           = rawPkt
	pd.isARPReply    = false
	pd.decodedLayers = pd.decodedLayers[:0]

	if err := pd.parser.DecodeLayers(pd.pkt, &pd.decodedLayers); err != nil {
		return
	}

	for _, layerType := range pd.decodedLayers {
		if layerType == layers.LayerTypeARP && pd.arp.Operation == layers.ARPReply {
			pd.isARPReply = true
			break
		}
	}
}



func (pd *PacketDissector) GetSrcMac() (net.HardwareAddr, bool) {
	if pd.isARPReply {
		return net.HardwareAddr(pd.arp.SourceHwAddress), true
	}

	if len(pd.decodedLayers) == 0 {
		return nil, false
	}

    if pd.eth.SrcMAC != nil {
		return pd.eth.SrcMAC, true
	}

    return nil, false
}



func (pd *PacketDissector) GetSrcIP() (net.IP, bool) {
	if pd.isARPReply {
		return net.IP(pd.arp.SourceProtAddress), true
	}

	for _, layerType := range pd.decodedLayers {
		if layerType == layers.LayerTypeIPv4 {
			return pd.ipv4.SrcIP, true
		}
	}

    return nil, false
}



func (pd *PacketDissector) GetTCPSrcPort() (uint16, bool) {
	hasIPv4 := false
	hasTCP  := false

	for _, lt := range pd.decodedLayers {
		switch lt {
		case layers.LayerTypeIPv4 : hasIPv4 = true
		case layers.LayerTypeTCP  : hasTCP  = true
		}
	}

	if hasIPv4 && hasTCP {
		return uint16(pd.tcp.SrcPort), true
	}
	
    return 0, false
}



func (pd *PacketDissector) GetUDPSrcPort() (uint16, bool) {
	hasIPv4 := false
	hasUDP  := false

	for _, lt := range pd.decodedLayers {
		switch lt {
		case layers.LayerTypeIPv4 : hasIPv4 = true
		case layers.LayerTypeUDP  : hasUDP  = true
		}
	}

	if hasIPv4 && hasUDP {
		return uint16(pd.udp.SrcPort), true
	}
	
    return 0, false
}