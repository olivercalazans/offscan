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

	bssid    := dot11.Address3.String()
	ssid     := "<hidden>"
	channel  := "0"
	sec 	 := "Open"
	standard := "802.11b/g"

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
			
			case layers.Dot11InformationElementIDHTCapabilities:
				standard = "802.11n"
			case layers.Dot11InformationElementIDVHTCapabilities:
				standard = "802.11ac"
			case 255: // HE Capabilities (802.11ax / Wi-Fi 6)
				if len(ie.Info) > 0 && ie.Info[0] == 35 {
					standard = "802.11ax"
				}

			// Segurança Avançada (RSN)
			case layers.Dot11InformationElementIDRSNInfo:
				sec = parseRSN(ie.Info)
			}
		}
	}

	// Checagem de WEP/802.11w via Flags do Beacon
	if beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beaconLayer != nil {
		b, _ := beaconLayer.(*layers.Dot11MgmtBeacon)
		
		// Bit de Privacy indica criptografia (WEP se RSN não estiver presente)
		if sec == "Open" && (uint16(b.Flags)&0x0010) != 0 {
			sec = "WEP"
		}
	}

	return []string{ssid, bssid, channel, sec, standard}, true
}

// Função auxiliar para processar o campo RSN (WPA2/WPA3/Management Frame Protection)
func parseRSN(data []byte) string {
	if len(data) < 2 {
		return "WPA2"
	}

	// O RSN possui uma estrutura fixa:
	// Version (2 bytes)
	// Group Cipher Suite (4 bytes)
	// Pairwise Cipher Suite Count (2 bytes)
	// Pairwise Cipher Suites (4 bytes cada)
	// AKM Suite Count (2 bytes)
	// AKM Suites (4 bytes cada)

	var auth, cipher string
	ptr := 2 // Pula a versão

	// 1. Group Cipher (Multicast)
	if len(data) >= ptr+4 {
		cipher = decodeCipher(data[ptr : ptr+4])
		ptr += 4
	}

	// 2. Pairwise Cipher Count (Unicast)
	if len(data) >= ptr+2 {
		count := int(data[ptr]) | int(data[ptr+1])<<8
		ptr += 2
		// Pegamos o primeiro Cipher Suite de Unicast disponível
		if count > 0 && len(data) >= ptr+4 {
			cipher = decodeCipher(data[ptr : ptr+4])
			ptr += (count * 4)
		}
	}

	// 3. AKM (Authentication Key Management)
	if len(data) >= ptr+2 {
		count := int(data[ptr]) | int(data[ptr+1])<<8
		ptr += 2
		if count > 0 && len(data) >= ptr+4 {
			auth = decodeAKM(data[ptr : ptr+4])
		}
	}

	// Verificação de 802.11w (Management Frame Protection)
	// Fica nos RSN Capabilities (2 bytes após as listas acima)
	mfp := ""
	// O mapeamento exato de bits aqui é complexo, 
	// mas simplificamos para o retorno:
	if auth == "SAE (WPA3)" {
		return "WPA3-" + cipher
	}
	
	if auth == "" { auth = "PSK" }
	return fmt.Sprintf("WPA2-%s-%s%s", auth, cipher, mfp)
}

func decodeCipher(suite []byte) string {
	if suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return "Unknown"
	}
	switch suite[3] {
	case 2: return "TKIP"
	case 4: return "CCMP(AES)"
	case 5: return "WEP"
	case 6: return "GCMP" // Comum em 802.11ad/ax
	default: return "Reserved"
	}
}

func decodeAKM(suite []byte) string {
	if suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return "Unknown"
	}
	switch suite[3] {
	case 1: return "802.1x"
	case 2: return "PSK"
	case 8: return "SAE (WPA3)"
	case 6: return "PSK-SHA256"
	default: return "Reserved"
	}
}

