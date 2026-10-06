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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"offscan/internal/argparser"
	"offscan/internal/utils"
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
	iface net.Interface
	mon   bool
	man   bool
}



func (im *ifaceMode) parseArgs(args []string) {
	parser := argparser.NewArgParser(args)

	args1    := argparser.Argument{Long: "--iface", Short: "-i", Required: true}
	iface, _ := parser.Iface(&args1)
	im.iface  = iface

	args2  := argparser.Argument{Long: "--mon", Short: "", Required: false}
	im.mon  = parser.Bool(&args2)

	args3  := argparser.Argument{Long: "--man", Short: "", Required: false}
	im.man  = parser.Bool(&args3)

	parser.AbortIfHasError()
}



func (im *ifaceMode) execute() {
	im.validateModeFlags()

	if im.mon {
		im.switchMode(nl80211IftypeMonitor, "monitor")
	}
	if im.man {
		im.switchMode(nl80211IftypeManaged, "managed")
	}
}



func (im *ifaceMode) validateModeFlags() {
	if !im.mon && !im.man { utils.Abort("It's necessary to select a mode: --mon or --man") }
	if im.mon && im.man   { utils.Abort("Select only one mode: --mon or --man") }
}



func (im *ifaceMode) switchMode(iftype uint32, label string) {
	wiphy, err := phyIndex(im.iface.Name)
	if err != nil {
		utils.Abort(fmt.Sprintf("Unable to resolve phy for %s: %v", im.iface.Name, err))
	}

	dev, err := newNL80211()
	if err != nil {
		utils.Abort(fmt.Sprintf("Unable to open nl80211 socket: %v", err))
	}
	defer dev.close()

	if err := setLinkUp(im.iface.Index, false); err != nil {
		utils.Abort(fmt.Sprintf("Unable to set interface %s down: %v", im.iface.Name, err))
	}

	if err := dev.deleteInterface(im.iface.Index); err != nil {
		utils.Abort(fmt.Sprintf("Unable to delete interface %s: %v", im.iface.Name, err))
	}
	
	if err := dev.createInterface(wiphy, im.iface.Name, iftype); err != nil {
		utils.Abort(fmt.Sprintf(
			"Unable to create interface %s on %s mode: %v", im.iface.Name, label, err,
		))
	}

	if link, err := net.InterfaceByName(im.iface.Name); err == nil {
		if err := setLinkUp(link.Index, true); err != nil {
			utils.Abort(fmt.Sprintf("Unable to set interface %s up: %v", im.iface.Name, err))
		}
	}
}



func phyIndex(iface string) (int, error) {
	path := filepath.Join("/sys/class/net", iface, "phy80211", "index")
	data, err := os.ReadFile(path)
	
	if err != nil {
		return 0, err
	}
	
	return strconv.Atoi(strings.TrimSpace(string(data)))
}