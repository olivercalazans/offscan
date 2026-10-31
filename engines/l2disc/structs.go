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

package l2disc

import "offscan/internal/models"

// alignment: 1 byte
type dot11Info struct {
    ssid      models.SSID  // 35 bytes (35 * byte)
    bssid     models.BSSID //  6 bytes 
    staMac    models.MAC   //  6 bytes 
    chnl      uint8        //  1 byte
    isBeacon  bool         //  1 byte
    isDataFrm bool         //  1 byte
}


// alignment: 1 byte
type beacon struct {
	ssid  models.SSID // 35 bytes (35 * byte)
	chnl  uint8
}


// alignment: 1 byte
type station struct {
	bssid   models.BSSID
	staMac  models.MAC
}