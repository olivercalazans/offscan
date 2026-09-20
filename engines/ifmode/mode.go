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

import (
	"fmt"
	"net"
	"offscan/internal/argparser"
	"offscan/internal/utils"
	"os/exec"
	"time"
)



func Run(args []string) {
    var im ifaceMode
	im.parseArgs(args)
	im.execute()
}



func DisplayHelp() {
	help := "\n### INTERFACE MODE\n\n" + 
	"    E.g., $ sudo ./offscan ifmode <FLAGS>\n\n" +
	"    -i, --iface : (Required) Interface\n" +
	"        --man   : (Option)   Set interface on maneged mode\n" +
	"        --mon   : (Option)   Set interface on monitor mode\n"

	fmt.Println(help)
}



type ifaceMode struct {
	iface  net.Interface
	mon    bool
	man    bool
}



func (im *ifaceMode) parseArgs(args []string) {
    parser := argparser.NewArgParser(args)

	args1    := argparser.Argument{ Long: "--iface", Short: "-i", Required: true }
	iface, _ := parser.Iface(&args1)
	im.iface  = iface

	args2  := argparser.Argument{ Long: "--mon", Short: "", Required: false }
	im.mon  = parser.Bool(&args2)

	args3  := argparser.Argument{ Long: "--man", Short: "", Required: false }
	im.man  = parser.Bool(&args3)

	parser.AbortIfHasError()
}



func (im *ifaceMode) execute() {
	im.validateModeFlags()

	if im.mon { im.setMonitorMode() }
	if im.man { im.setManagedMode() }
}



func (im *ifaceMode) validateModeFlags() {
	if !im.mon && !im.man {
		utils.Abort("It's necessary to select a mode: --mon or --man")
	}

	if im.mon && im.man {
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



func (im *ifaceMode) setIfaceDown() {
	cmd := exec.Command("sudo", "ip", "link", "set", im.iface.Name, "down")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to set interface %s down: %v", im.iface.Name, err))
	}
}



func (im *ifaceMode) setIfaceUp() {
	cmd := exec.Command("sudo", "ip", "link", "set", im.iface.Name, "up")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to set interface %s up: %v", im.iface.Name, err))
	}
}



func (im *ifaceMode) delIface() {
	cmd := exec.Command("sudo", "iw", "dev", im.iface.Name, "del")
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to delete interface %s: %v", im.iface.Name, err))
	}
}



func (im *ifaceMode) createIface(mode string) {
	cmd := exec.Command("sudo", "iw", "phy", "phy0", "interface", "add", im.iface.Name, "type", mode)
	
	if err := handler(cmd); err != nil {
		utils.Abort(
			fmt.Sprintf("Unable to create interface %s on %s mode: %v", im.iface.Name, mode, err))
	}
}



func (im *ifaceMode) setMonitorMode() {
	im.setIfaceDown()
	im.delIface()
	im.createIface("monitor")
	im.setIfaceUp()	
}



func (im *ifaceMode) setManagedMode() {
	im.setIfaceDown()
	im.delIface()
	im.createIface("managed")
	im.setIfaceUp()	
}