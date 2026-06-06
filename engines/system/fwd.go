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

package system

import (
	"bytes"
	"fmt"
	"offscan/internal/utils"
	"os"
)



func (s *system) executeFwd() {
	s.validateFwdFlags()

	if s.enable  { enableIPv4Forwarding()  }
	if s.disable { disableIPv4Forwarding() }
}



func (s *system) validateFwdFlags() {
	if s.enable && s.disable {
		utils.Abort("Both enable and disable flags are provided, but only one can be used at a time")
	}

	if !s.enable && !s.disable {
		utils.Abort("No action flag provided. It's necessary to use -e/--enable or -d/--disable")
	}
}



const ipv4ForwardPath = "/proc/sys/net/ipv4/ip_forward"


func isIPv4ForwardingEnabled() bool {
    content, err := os.ReadFile(ipv4ForwardPath)
	
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to read %s: %v", ipv4ForwardPath, err))
    }

	return bytes.TrimSpace(content)[0] == '1'
}



func enableIPv4Forwarding() {
    enabled := isIPv4ForwardingEnabled()
    if enabled {
		fmt.Println("[#] Forwarding already enabled")
    }

    if err := os.WriteFile(ipv4ForwardPath, []byte{'1'}, 0644); err != nil {
        utils.Abort(fmt.Sprintf("Failed to enable IP forwarding: %v", err))
    }
}



func disableIPv4Forwarding() {
	enabled := isIPv4ForwardingEnabled()
    if !enabled {
		fmt.Println("[#] Forwarding already enabled")
    }

    if err := os.WriteFile(ipv4ForwardPath, []byte{'0'}, 0644); err != nil {
        utils.Abort(fmt.Sprintf("Failed to disable IP forwarding: %v", err))
    }
}