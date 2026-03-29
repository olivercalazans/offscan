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

import (
	"net"
)



type WifiData struct {
    BSSIDs   map[string]struct{}
    Channel  uint8
    Freq     string
    Sec      string
}



func NewWifiData(bssid net.HardwareAddr, channel uint8, freq, sec string) *WifiData {
    bssids := make(map[string]struct{})
    bssids[bssid.String()] = struct{}{}
    
	return &WifiData{
        BSSIDs:  bssids,
        Channel: channel,
        Freq:    freq,
        Sec:     sec,
    }
}