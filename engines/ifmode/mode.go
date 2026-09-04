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
	"offscan/internal/conv"
	"offscan/internal/utils"
	"os/exec"
	"time"
)



func Run(args []string) {
    var im ifaceMode
	
	im.parseArgs(args)
	args = nil

	im.execute()
}



const (
	iface = iota
	mon
	man
)



func DisplayHelp() {
	help := "\n# INTERFACE MODE. E.g., $ sudo ./offscan ifmode <FLAGS>\n\n" +
	"    -i, --iface : (Required) Interface\n" +
	"        --man   : (Option)   Set interface on maneged mode\n" +
	"        --mon   : (Option)   Set interface on monitor mode\n"

	fmt.Println(help)
}



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: iface, Short: "i", Long: "iface", HasValue: true},	
		{ID: mon,   Long: "mon"},
		{ID: man,   Long: "man"},
	}
}



type ifaceMode struct {
	iface  net.Interface
	mon    bool
	man    bool
}



func (im *ifaceMode) parseArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)

	for _, flag := range flags {
		switch flag.ID {
		case iface : im.iface = conv.MustStrToIface(flag.ValueStr)
		case mon   : im.mon   = flag.ValueBool
		case man   : im.man   = flag.ValueBool
		}
	}
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