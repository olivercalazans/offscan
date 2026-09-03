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

package dot11dissec

import (
	"encoding/binary"
	"offscan/internal/models"
)



func (dd *Dot11Dissector) GetWPS() models.WPSInfo {
	var info models.WPSInfo

	if len(dd.wpsData) == 0 {
		return info
	}

	dd.parseWPS(&info)
	return info
}



func (dd *Dot11Dissector) parseWPS(info *models.WPSInfo) {
	lenData := len(dd.wpsData)
	pos := 0

	for pos+4 <= lenData {
		t := binary.BigEndian.Uint16(dd.wpsData[pos : pos+2])
		l := int(binary.BigEndian.Uint16(dd.wpsData[pos+2 : pos+4]))

		if pos + 4 + l > lenData { break }

		val := dd.wpsData[pos+4 : pos+4+l]

		switch t {
		case 0x104A: if l >= 1 { info.Version = int(val[0]) }
		case 0x1044: if l >= 1 { info.IsConfigured = val[0] == 1 }
		case 0x1057: if l >= 1 { info.APSetupLocked = val[0] != 0 }
		case 0x1008, 0x1053: if l >= 2 { info.ConfigMethods = binary.BigEndian.Uint16(val) }
		}

		pos += 4 + l
	}

	if info.Version == 0 { info.Version = 0x10 }
}