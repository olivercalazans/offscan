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

package argparser

import (
	"fmt"
	"offscan/internal/utils"
)


type Flag struct {
    destBool     *bool
    destStr      *string
    name          string
    short         string
    long          string
    hasValue      bool
    description   string
}


type ArgParser struct {
    flagsInfo  []Flag
    flags      []string
    args       []string
}



func NewArgParser(flags []Flag, args []string) *ArgParser {
    return &ArgParser{
		flagsInfo : flags,
        args      : args,
	}
}



func (ap *ArgParser) ParseFlags() {
    ap.saveAllFlags()
    ap.parseFlagsWithValue()
}



func (ap *ArgParser) saveAllFlags() {
    for _, flag := range ap.flagsInfo {
        if flag.short != "" { ap.flags = append(ap.flags, flag.short) }
        if flag.long  != "" { ap.flags = append(ap.flags, flag.long) }
    }
}



func (ap *ArgParser) parseFlagsWithValue() {
	for _, flag := range ap.flagsInfo {
		if !flag.hasValue { continue }
		
		short, long := ap.checkForDuplicates(&flag)
		
		
	}
}


func (ap *ArgParser) checkForDuplicates(flag *Flag) (uint8, uint8) {
	var shortTimes, longTimes uint8 

	for _, arg := range ap.args {
		if arg == flag.short { shortTimes++ } 
		if arg == flag.long  { longTimes++ }
	}

	if shortTimes + longTimes > 1 {
		utils.Abort(fmt.Sprintf("Flag used more than once: %s %s", flag.short, flag.long))
	}

	return shortTimes, longTimes
}