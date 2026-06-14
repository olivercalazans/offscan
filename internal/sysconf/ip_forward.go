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

package sysconf

import (
	"fmt"
	"offscan/internal/utils"
	"os"
)


const path string = "/proc/sys/net/ipv4/ip_forward"



func MustEnableIPForwarding() {
    err := os.WriteFile(path, []byte("1"), 0644)

	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to enable IP forwarding %s: %v", path, err))
    }
}



func MustDisableIPForwarding() {
    err := os.WriteFile(path, []byte("0"), 0644)

	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to disable IP forwarding %s: %v", path, err))
    }
}