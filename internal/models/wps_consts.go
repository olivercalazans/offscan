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

package models


const ( // WPS STATE
	wpsVersionMask = 0x03
	wpsConfigMask  = 1 << (iota + 2)  // 1 << (1 + 2) = 0x08
	wpsAPSetupLocked                  // 1 << (2 + 2) = 0x10
	wpsStatePresent                   // 1 << (3 + 2) = 0x20
	wpsSelectedRegistrar              // 1 << (4 + 2) = 0x40
)

const ( // PRESENCE FLAGS
	passwordID = iota
	configMethods
	rfBands
	devType
)

const (
	passIDDefault    uint16 = 0x0000
	passIDUserSpec   uint16 = 0x0001
	passIDMachine    uint16 = 0x0002
	passIDRekey      uint16 = 0x0003
	passIDPushButton uint16 = 0x0004
	passIDRegSpec    uint16 = 0x0005
)

const (
	configMethodUSBA       uint16 = 1 << 0
	configMethodEthernet   uint16 = 1 << 1
	configMethodLabel      uint16 = 1 << 2
	configMethodDisplay    uint16 = 1 << 3
	configMethodExtNFC     uint16 = 1 << 4
	configMethodIntNFC     uint16 = 1 << 5
	configMethodNFCIntf    uint16 = 1 << 6
	configMethodPushButton uint16 = 1 << 7
	configMethodKeypad     uint16 = 1 << 8
)

const (
	rfBand24GHz uint8 = 1 << 0
	rfBand5GHz  uint8 = 1 << 1
	rfBand60GHz uint8 = 1 << 2
)