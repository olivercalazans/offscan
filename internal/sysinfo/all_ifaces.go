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

package sysinfo

import (
	"fmt"
	"net"
	"offscan/internal/utils"
)



func MustAllIfaces() []net.Interface {
	interfaces, err := net.Interfaces()
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to get interface list: %v", err))
    }

	return interfaces
}