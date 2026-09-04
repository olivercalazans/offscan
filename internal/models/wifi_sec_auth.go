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



type SecurityAuth uint8

const (
	AuthNone SecurityAuth = iota
	AuthPSK
	AuthMGT
	AuthSAE
	AuthOWE
	AuthAPPeer
)



func (sa SecurityAuth) str() string {
	switch sa {
	case AuthPSK    : return "PSK"
	case AuthMGT    : return "MGT"
	case AuthSAE    : return "SAE"
	case AuthOWE    : return "OWE"
	case AuthAPPeer : return "AP-PEER"
	default         : return ""
	}
}



func (sa SecurityAuth) lenStr() int {
	switch sa {
	case AuthPSK    : return 3
	case AuthMGT    : return 3
	case AuthSAE    : return 3
	case AuthOWE    : return 3
	case AuthAPPeer : return 7
	default         : return 0
	}
}