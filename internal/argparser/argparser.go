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
	"os"
	"slices"
	"sort"
	"strings"
)


type Flag struct {
    ID         uint8
    ValueBool  bool
    ValueStr   string
    Short      string
    Long       string
    HasValue   bool
    Desc       string
}


type ArgParser struct {
    flags     []Flag
    flagList  []string
    args      []string
}



func NewArgParser(flags []Flag, args []string) *ArgParser {
    return &ArgParser{
		flags : flags,
        args  : args,
	}
}



func (ap *ArgParser) ParseFlags() {
    ap.saveAllFlags()
    ap.verifyIfHasTheHelper()
    ap.parseFlagsWithValue()
    ap.parseBoolFlags()
    ap.checkForRemaining()
}



func (ap *ArgParser) saveAllFlags() {
    for i := range ap.flags {
        flag := &ap.flags[i]
        
        if flag.Short != "" {
            flag.Short  = fmt.Sprintf("-%s", flag.Short)
            ap.flagList = append(ap.flagList, flag.Short)
        }
        
        if flag.Long  != "" {
            flag.Long   = fmt.Sprintf("--%s", flag.Long)
            ap.flagList = append(ap.flagList, flag.Long)
        }
    }
}



func (ap *ArgParser) verifyIfHasTheHelper() {
    indexShort := slices.Index(ap.args, "-h")
    indexLong  := slices.Index(ap.args, "--help")

    if indexShort > -1 || indexLong > -1 {
        ap.displayDescriptions()
    }
}



func (ap *ArgParser) displayDescriptions() {
    sort.Slice(ap.flags, func(i, j int) bool {
        return ap.flags[i].ID < ap.flags[j].ID
    })

    for _, f := range ap.flags {
        fmt.Printf("%s, %s : %s\n", f.Short, f.Long, f.Desc)
    }

    os.Exit(0)
}



func (ap *ArgParser) parseFlagsWithValue() {
    if len(ap.args) <= 0 { return }

    for i := range ap.flags {
        flag := &ap.flags[i]
		if !flag.HasValue { continue }
		
		short, long := ap.checkIfIsUsed(flag)
        if !short && !long { continue }
		
        if short { flag.ValueStr = ap.processFlagAndValue(flag.Short) }
        if long  { flag.ValueStr = ap.processFlagAndValue(flag.Long)  }
	}
}



func (ap *ArgParser) checkIfIsUsed(flag *Flag) (bool, bool) {
	var shortTimes, longTimes uint8 

	for _, arg := range ap.args {
		if arg == flag.Short { shortTimes++ } 
		if arg == flag.Long  { longTimes++  }
	}

	if shortTimes + longTimes > 1 {
		utils.Abort(fmt.Sprintf("Flag used more than once: %s %s", flag.Short, flag.Long))
	}

	return shortTimes > 0, longTimes > 0
}



func (ap *ArgParser) processFlagAndValue(flag string) string {
    index   := slices.Index(ap.args, flag)
    value   := ap.validateValue(flag, index)
    ap.args  = slices.Delete(ap.args, index, index + 2)
    return value
}



func (ap *ArgParser) validateValue(flag string, flagIndex int) string {
    valueIndex := flagIndex + 1

    if valueIndex >= len(ap.args) {
        utils.Abort(fmt.Sprintf("Missing value for flag: %s", flag))
    }

    value := ap.args[valueIndex]

    for _, arg := range ap.flagList {
        if arg == value {
            utils.Abort(fmt.Sprintf("Missing value for flag: %s", flag))
        }
    }

    return value
}



func (ap *ArgParser) parseBoolFlags() {
    if len(ap.args) <= 0 { return }

    for i := range ap.flags {
        flag := &ap.flags[i]
		if flag.HasValue { continue }
		
        short, long := ap.checkIfIsUsed(flag)
        if !short && !long { continue }

		var index int

        if short { index = slices.Index(ap.args, flag.Short) }
        if long  { index = slices.Index(ap.args, flag.Long)  }

        ap.args        = slices.Delete(ap.args, index, index + 1)
        flag.ValueBool = short || long
	}
}



func (ap *ArgParser) checkForRemaining() {
    if len(ap.args) > 0 {
        unknown := strings.Join(ap.args, ", ")
        utils.Abort(fmt.Sprintf("Unknown flags: %s", unknown))
    }
}