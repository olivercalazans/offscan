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

package wifimap

import "offscan/internal/models"

// alignment: 2 bytes
type wifiData struct {
    time  models.Uptime  //  4 bytes
    bssid models.BSSID   //  6 bytes
    sec   models.WifiSec //  4 bytes
    ssid  models.SSID    // 35 bytes
    std   models.WifiStd //  1 byte 
    wps   models.WPSInfo //  1 byte 
    chnl  uint8          //  1 byte 
}



// alignment: 8 bytes
type maxLength struct {
    ssid int // 8 bytes
    sec  int // 8 bytes
    wps  int // 8 bytes
}