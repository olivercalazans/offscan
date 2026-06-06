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
	"fmt"
	"offscan/internal/utils"
	"os/exec"
	"time"
)



func (s *system) executeMode() {
	s.validateModeFlags()

	if s.mon { s.setMonitorMode() }
	if s.man { s.setManagedMode() }
}



func (s *system) validateModeFlags() {
	if !s.mon && !s.man {
		utils.Abort("It's necessary to select a mode: --mon or --man")
	}

	if s.mon && s.man {
		utils.Abort("Select only one mode: --mon or --man")
	}
}



func handler(cmd *exec.Cmd) *string {
    err := cmd.Run()
    
	if err != nil {
        msg := fmt.Sprintf("%s", err)
        return &msg
    }
    
	time.Sleep(1e8)
    return nil
}



func (s *system) setIfaceDown() {
	cmd := exec.Command("sudo", "ip", "link", "set", s.iface.Name, "down")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to set interface %s down: %v", s.iface.Name, err))
	}
}



func (s *system) setIfaceUp() {
	cmd := exec.Command("sudo", "ip", "link", "set", s.iface.Name, "up")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to set interface %s up: %v", s.iface.Name, err))
	}
}



func (s *system) delIface() {
	cmd := exec.Command("sudo", "iw", "dev", s.iface.Name, "del")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to delete interface %s: %v", s.iface.Name, err))
	}
}



func (s *system) createIface(mode string) {
	cmd := exec.Command("sudo", "iw", "phy", "phy0", "interface", "add", s.iface.Name, "type", mode)
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to create interface %s on %s mode: %v", s.iface.Name, mode, err))
	}
}



func (s *system) setMonitorMode() {
	s.setIfaceDown()
	s.delIface()
	s.createIface("monitor")
	s.setIfaceUp()	
}



func (s *system) setManagedMode() {
	s.setIfaceDown()
	s.delIface()
	s.createIface("managed")
	s.setIfaceUp()	
}