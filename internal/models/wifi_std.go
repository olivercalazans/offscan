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

type WifiStd uint8


const (
    StdUnknown WifiStd = iota
    StdB_G    // 802.11b/g
    StdN      // 802.11n
    StdAC     // 802.11ac
    StdAX     // 802.11ax
)



func (s WifiStd) String() string {
    switch s {
    case StdB_G: return "802.11b/g"
    case StdN:   return "802.11n"
    case StdAC:  return "802.11ac"
	case StdAX:  return "802.11ax"
    default:     return "unknown"
    }
}