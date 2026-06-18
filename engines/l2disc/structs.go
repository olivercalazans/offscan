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


type dot11Info struct {
	isBeacon   bool
	bssid      [6]byte
	ssid       string
	chnl       uint8
	isDataFrm  bool
	staMac     [6]byte
}


type buffers struct {
	nets  map[[6]byte]beacon
	stas  map[station]struct{}
	miss  map[station]struct{}
}


type beacon struct {
	ssid  string
	chnl  uint8
}


type station struct {
	bssid   [6]byte
	staMac  [6]byte
}