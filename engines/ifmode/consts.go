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

package ifmode


const (
	nl80211FamilyName = "nl80211"

	nl80211CmdNewInterface = 7
	nl80211CmdDelInterface = 8

	nl80211AttrWiphy   = 1
	nl80211AttrIfindex = 3
	nl80211AttrIfname  = 4
	nl80211AttrIftype  = 5

	nl80211IftypeManaged = 2 // NL80211_IFTYPE_STATION
	nl80211IftypeMonitor = 6 // NL80211_IFTYPE_MONITOR

	rtmNewlink = 16

	iffUp = 0x1

	nlmFRequest = 0x01
	nlmFAck     = 0x04

	genlIDCtrl         = 0x10
	ctrlCmdGetFamily   = 3
	ctrlAttrFamilyID   = 1
	ctrlAttrFamilyName = 2
)