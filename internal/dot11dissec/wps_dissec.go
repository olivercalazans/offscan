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



func (dd *Dot11Dissector) GetWPS() *WPSInfo {
	if !dd.IsBeacon || dd.wpsData == nil {
		return nil
	}
	return parseWPS(dd.wpsData)
}



type WPSInfo struct {
	Version        int
	State          int 
	ConfigMethods  uint16
	APSetupLocked  bool
}



func parseWPS(data []byte) *WPSInfo {
	lenData := len(data)
	wps     := &WPSInfo{}
	pos     := 0

	for pos + 4 <= lenData {
		t := binary.BigEndian.Uint16(data[pos : pos+2])
		l := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
	
		if pos + 4 + l > lenData { break }
		
		val := data[pos+4 : pos+4+l]
		
		switch t {
		// Version
		case 0x104A: if l >= 1 { wps.Version = int(val[0]) }
		// WPS State
		case 0x1044: if l >= 1 { wps.State = int(val[0]) }
		// AP Setup Locked
		case 0x1057: if l >= 1 { wps.APSetupLocked = val[0] != 0 }
		// Config Methods
		case 0x1008, 0x1053:
			if l >= 2 { wps.ConfigMethods = binary.BigEndian.Uint16(val) }
		}

		pos += 4 + l
	}
	
	if wps.Version == 0 { wps.Version = 0x10 }

	return wps
}