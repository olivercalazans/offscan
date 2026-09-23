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

package wifimap

import (
	"fmt"
	"offscan/internal/argparser"
)



func DisplayHelp() {
	help := "\n### WIFI MAPPER\n\n" + 
	"    E.g., $ sudo ./offscan wmap <FLAGS>\n\n" +
	"    -i, --iface <IFACE> : (Required) Interface to be used to sniff\n"

	fmt.Println(help)
}



type wmParser struct {
	engine  *wifiMapper
	parser  *argparser.ArgParser
}



func (wm *wifiMapper) parseArgs(args []string) {
	wmp := wmParser{}

	wmp.engine = wm
	wmp.parser = argparser.NewArgParser(args)
	
	wmp.getIface()
	wmp.parser.AbortIfHasError()
}



func (wmp *wmParser) getIface() {
	arg := argparser.Argument{ Long: "--iface", Short: "-i", Required: true }

	iface, _ := wmp.parser.Iface(&arg)
	
	wmp.engine.iface  = iface
}