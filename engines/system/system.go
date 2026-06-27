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
	"net"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/utils"
)


func Run(args []string) {
    s := system{}
	s.parseArgs(args)
	s.validateCmdFlags()
	s.execute()
}


type system struct {
	flags  []argparser.Flag

	iface  *net.Interface
	info    bool
	
	mode   bool
	mon    bool
	man    bool

	fwd      bool
	enable   bool
	disable  bool
}



const (
	iface    uint8 = 1
	info     uint8 = 10
	mode     uint8 = 20
	mon      uint8 = 21
	man      uint8 = 22
	fwd      uint8 = 30
	enable   uint8 = 31
	disable  uint8 = 32
)



func DisplayHelp() {
	help := "\n# Interface and system configuration. E.g., $ sudo ./offscan sys <FLAGS>\n\n" +
	"    -I, --info    : (Command 1)  Set monitor or managed mode on interface\n" +
	"    -F, --forward : (Command 2) Set monitor or managed mode on interface\n" +
	"    -e, --enable  : (Req CMD 2) Enable forwarding\n" +
	"    -d, --disable : (Req CMD 2) Disable forwarding\n" +	
	"    -M, --mode    : (Command 3) Set monitor or managed mode on interface\n" +
	"        --mon     : (Req CMD 3) Set interface on monitor mode\n" +
	"        --man     : (Req CMD 3) Set interface on maneged mode\n" +
	"    -i, --iface   : (Req All CMD) Interface\n" +
	"\n    OBS.: Only ONE command can be used at a time\n"

	fmt.Println(help)
}



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: iface,   Short: "i", Long: "iface", HasValue: true},
		{ID: info,    Short: "I", Long: "info"},		
		{ID: mode,    Short: "M", Long: "mode"},		
		{ID: mon,     Short: "",  Long: "mon"},
		{ID: man,     Short: "",  Long: "man"},
		{ID: fwd,     Short: "F", Long: "forward"},
		{ID: enable,  Short: "e", Long: "enable"},
		{ID: disable, Short: "d", Long: "disable"},
	}
}



func (s *system) parseArgs(args []string) {
    s.flags  = FlagSettings()
	parser  := argparser.NewArgParser(s.flags)
	parser.ParseFlags(args)
	args = nil

	for _, flag := range s.flags {
		switch flag.ID {
		case iface   : s.iface   = conv.StrToIface(flag.ValueStr)
		case info    : s.info    = flag.ValueBool
		case mode    : s.mode    = flag.ValueBool
		case mon     : s.mon     = flag.ValueBool
		case man     : s.man     = flag.ValueBool
		case fwd     : s.fwd     = flag.ValueBool
		case enable  : s.enable  = flag.ValueBool
		case disable : s.disable = flag.ValueBool
		}
	}
}



func (s *system) validateCmdFlags() {
	var count uint8

	if s.info { count++ }
	if s.mode { count++ }
	if s.fwd  { count++ }

	if count > 1 {
		str := s.getCmdStr()
		utils.Abort(fmt.Sprintf("Only command can be used at a time:\n%s", str))
	}

	if count <= 0 {
		str := s.getCmdStr()
		utils.Abort(fmt.Sprintf("One of these flags must be used:\n%s", str))
	}
}



func (s *system) getCmdStr() string {
	cmds    := s.getCmdFlags()
    descLen := argparser.GetFlagMaxLen(cmds)
	var str string

    for _, f := range cmds {
        flags := argparser.GetInlineFlags(&f)		
        str   += fmt.Sprintf("%-*s, ", descLen, flags)
    }

	return str
}



func (s *system) getCmdFlags() []argparser.Flag {
	lookFor := [3]uint8{info, mode, fwd}
	cmds    := []argparser.Flag{}
	
	for _, id := range lookFor {
		for _, cmd := range s.flags {
			if cmd.ID == id {
				cmds = append(cmds, cmd)
			}
		}
	}

	return cmds
}



func (s *system) execute() {
	if s.mode { s.executeMode() }
	if s.info { s.executeInfo() }
	if s.fwd  { s.executeFwd()  }
}