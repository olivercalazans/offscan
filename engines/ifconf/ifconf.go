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

package ifconf

import (
	"fmt"
	"offscan/internal/conv"
	"offscan/internal/utils"
	"os/exec"
	"time"
)



func Run(args []string) {
    newIfaceConfig(args).execute()
}



type ifaceConfig struct {
	args  *ifConfArgs
}



func newIfaceConfig(args []string) *ifaceConfig {
	return &ifaceConfig{
		args: parseIfConfigArgs(args),
	}
}



func (ic *ifaceConfig) execute() {
	ic.validateFlags()

	if ic.args.Mon {
		ic.setMonitorMode()
	}

	if ic.args.Man {
		ic.setManagedMode()
	}
}



func (ic *ifaceConfig) validateFlags() {
	if !ic.args.Mon && !ic.args.Man {
		utils.Abort("It's necessary to select a mode: --mon or --man")
	}

	if ic.args.Mon && ic.args.Man {
		utils.Abort("Select only one mode: --mon or --man")
	}

	conv.MustStrToIface(ic.args.Iface)
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



func (ic *ifaceConfig) setIfaceDown() {
	cmd := exec.Command("sudo", "ip", "link", "set", ic.args.Iface, "down")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to set interface %s down: %v", ic.args.Iface, err))
	}
}



func (ic *ifaceConfig) setIfaceUp() {
	cmd := exec.Command("sudo", "ip", "link", "set", ic.args.Iface, "up")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to set interface %s up: %v", ic.args.Iface, err))
	}
}



func (ic *ifaceConfig) delIface() {
	cmd := exec.Command("sudo", "iw", "dev", ic.args.Iface, "del")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to delete interface %s: %v", ic.args.Iface, err))
	}
}



func (ic *ifaceConfig) createIface(mode string) {
	cmd := exec.Command("sudo", "iw", "phy", "phy0", "interface", "add", ic.args.Iface, "type", mode)
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to create interface %s on %s mode: %v", ic.args.Iface, mode, err))
	}
}



func (ic *ifaceConfig) setMonitorMode() {
	ic.setIfaceDown()
	ic.delIface()
	ic.createIface("monitor")
	ic.setIfaceUp()	
}



func (ic *ifaceConfig) setManagedMode() {
	ic.setIfaceDown()
	ic.delIface()
	ic.createIface("managed")
	ic.setIfaceUp()	
}