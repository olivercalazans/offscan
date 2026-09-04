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



type SecurityCipher uint8

const (
	CipherNone SecurityCipher = iota
	CipherWEP
	CipherTKIP
	CipherCCMP
	CipherWEP104
	CipherGCMP
	CipherGCMP256
	CipherCCMP256
)



func (sc SecurityCipher) str() string {
	switch sc {
	case CipherWEP     : return "WEP"
	case CipherTKIP    : return "TKIP"
	case CipherCCMP    : return "CCMP"
	case CipherWEP104  : return "WEP104"
	case CipherGCMP    : return "GCMP"
	case CipherGCMP256 : return "GCMP-256"
	case CipherCCMP256 : return "CCMP-256"
	default	           : return ""
	}
}



func (sc SecurityCipher) lenStr() int {
	switch sc {
	case CipherWEP     : return 3
	case CipherTKIP    : return 4
	case CipherCCMP    : return 4
	case CipherWEP104  : return 6
	case CipherGCMP    : return 4
	case CipherGCMP256 : return 8
	case CipherCCMP256 : return 8
	default	           : return 0
	}
}