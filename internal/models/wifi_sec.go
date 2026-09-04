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

import "fmt"


type SecurityType uint8

const (
	SecTypeNone SecurityType = iota
	SecTypeOpen
	SecTypeWEP
	SecTypeWPA
)


type WifiSec struct {
	Type     SecurityType
	Version  uint8
	Auth     SecurityAuth
	Cipher   SecurityCipher
}



func (ws WifiSec) String() string {
	switch ws.Type {
	case SecTypeOpen : return "OPEN"
	case SecTypeWEP  : return "WEP"
	case SecTypeWPA  : return ws.wpaStrFlag()
	default          : return "unknown"
	}
}



func (ws WifiSec) wpaStrFlag() string {
	ver := "WPA"

	if ws.Version == 2 {
		if ws.isWPA3() {
			ver = "WPA3"
		} else {
			ver = "WPA2"
		}
	}

	authStr   := ws.Auth.str()
	cipherStr := ws.Cipher.str()

	if authStr == "" && cipherStr == "" {
		return ver
	}

	return fmt.Sprintf("%s-%s-%s", ver, authStr, cipherStr)
}



func (ws WifiSec) isWPA3() bool {
	return ws.Auth == AuthSAE || ws.Auth == AuthOWE
}



func (ws WifiSec) Len() int {
    switch ws.Type {
    case SecTypeOpen : return 4    // "OPEN"
    case SecTypeWEP  : return 3    // "WEP"
    case SecTypeWPA  : return ws.wpaStrLen()
    default          : return 7    // "unknown"
    }
}




func (ws WifiSec) wpaStrLen() int {

    if ws.Version == 1 {
        return 3   // "WPA"
	}

    if ws.isWPA3() {
        return 4  
    }

	total := 4

	authLen := ws.Auth.lenStr()
    if authLen > 0 {
        total += 1 + authLen      // espace + auth
    }

	cipherLen := ws.Cipher.lenStr()
    if cipherLen > 0 {
        total += 1 + cipherLen    // espace + cipher
    }

    return total
}