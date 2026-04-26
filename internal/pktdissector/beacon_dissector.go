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
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)



func DissecBeacon(data []byte) ([]string, bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)
	
	if packet.Layer(layers.LayerTypeDot11) == nil {
		packet = gopacket.NewPacket(data, layers.LayerTypeDot11, gopacket.Default)
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, false
	}

    dot11, _ := dot11Layer.(*layers.Dot11)

	if dot11.Type != layers.Dot11TypeMgmtBeacon {
		return nil, false
	}

	bssid   := dot11.Address3.String()
	ssid    := "<hidden>"
	channel := "0"
	sec     := "Open"

	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeDot11InformationElement {
			ie, _ := layer.(*layers.Dot11InformationElement)

			switch ie.ID {
			case layers.Dot11InformationElementIDSSID:
				if len(ie.Info) > 0 {
					ssid = string(ie.Info)
				}
			case layers.Dot11InformationElementIDDSSet:
				if len(ie.Info) > 0 {
					channel = fmt.Sprintf("%d", ie.Info[0])
				}
			case 48: 
				sec = "WPA2"
			}
		}
	}

	if beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beaconLayer != nil {
		b, _ := beaconLayer.(*layers.Dot11MgmtBeacon)

        if sec == "Open" && (uint16(b.Flags) & 0x0010) != 0 {
			sec = "WEP"
		}
	}

	return []string{ssid, bssid, channel, sec}, true
}