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
    Req        bool
}


type ArgParser struct {
    flagSettins  []Flag
    flagList     []string
    args         []string
}



func NewArgParser(flags []Flag, args []string) *ArgParser {
    return &ArgParser{
		flagSettins : flags,
        args  : args,
	}
}



func (ap *ArgParser) ParseFlags() {
    ap.saveAllFlags()
    ap.checkHelp()
    ap.checkRequired()
    ap.parseFlagsWithValue()
    ap.parseBoolFlags()
    ap.abortIfUnexpected()
}



func (ap *ArgParser) saveAllFlags() {
    for i := range ap.flagSettins {
        flag := &ap.flagSettins[i]
        
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



func (ap *ArgParser) checkHelp() {
    indexShort := slices.Index(ap.args, "-h")
    indexLong  := slices.Index(ap.args, "--help")

    if (indexShort > -1 || indexLong > -1) && len(ap.args) == 1 {
        ap.displayDescriptions()
    }
}



func (ap *ArgParser) displayDescriptions() {
    sort.Slice(ap.flagSettins, func(i, j int) bool {
        return ap.flagSettins[i].ID < ap.flagSettins[j].ID
    })

    descLen := ap.getFlagMaxLen()

    for _, f := range ap.flagSettins {
        flags := getFormatedFlags(&f)
        fmt.Printf("%-*s : %s\n", descLen, flags, f.Desc)
    }

    os.Exit(0)
}



func (ap *ArgParser) checkRequired() {
    var missingFlags []string

    for _, f := range ap.flagSettins {
        if !f.Req { continue }

        if !ap.hasFlag(&f) {
            missingFlags = append(missingFlags, getFormatedFlags(&f))
        }
    }

    if len(missingFlags) > 0 {
        err   := strings.Join(missingFlags, "\n")
        utils.Abort(fmt.Sprintf("Missing required flags:\n%s", err))
    }
}



func (ap *ArgParser) hasFlag(flag *Flag) bool {
    for _, a := range ap.args {
        if flag.Short == a || flag.Long == a {
            return true
        }
    }

    return false
}



func (ap *ArgParser) getFlagMaxLen() int {
    var maxLen int

    for _, f := range ap.flagSettins {
        str := getFormatedFlags(&f)
        len := len(str)
        
        if len > maxLen { maxLen = len }
    }

    return maxLen
}



func getFormatedFlags(flag *Flag) string {
    var flags []string
        
    if flag.Short != "" { flags = append(flags, flag.Short) }
    if flag.Long  != "" { flags = append(flags, flag.Long)  }
    
    return  strings.Join(flags, ", ")
}



func (ap *ArgParser) parseFlagsWithValue() {
    if len(ap.args) <= 0 { return }

    for i := range ap.flagSettins {
        flag := &ap.flagSettins[i]
		if !flag.HasValue { continue }
		
		short, long := ap.checkUsage(flag)
        if !short && !long { continue }
		
        if short { flag.ValueStr = ap.processFlagAndValue(flag.Short) }
        if long  { flag.ValueStr = ap.processFlagAndValue(flag.Long)  }
	}
}



func (ap *ArgParser) checkUsage(flag *Flag) (bool, bool) {
	var shortTimes, longTimes uint8 

	for _, arg := range ap.args {
		if arg == flag.Short { shortTimes++ } 
		if arg == flag.Long  { longTimes++  }
	}

	if shortTimes + longTimes > 1 {
        str := getFormatedFlags(flag)
		utils.Abort(fmt.Sprintf("Flag used more than once: %s", str))
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

    if strings.HasPrefix(value, "-") {
        utils.Abort(fmt.Sprintf("Missing value for flag: %s", flag))
    }

    for _, arg := range ap.flagList {
        if arg == value {
            utils.Abort(fmt.Sprintf("Missing value for flag: %s", flag))
        }
    }

    return value
}



func (ap *ArgParser) parseBoolFlags() {
    if len(ap.args) <= 0 { return }

    for i := range ap.flagSettins {
        flag := &ap.flagSettins[i]
		if flag.HasValue { continue }
		
        short, long := ap.checkUsage(flag)
        if !short && !long { continue }

		var index int

        if short { index = slices.Index(ap.args, flag.Short) }
        if long  { index = slices.Index(ap.args, flag.Long)  }

        ap.args        = slices.Delete(ap.args, index, index + 1)
        flag.ValueBool = short || long
	}
}



func (ap *ArgParser) abortIfUnexpected() {
    if len(ap.args) > 0 {
        unknown := strings.Join(ap.args, ", ")
        utils.Abort(fmt.Sprintf("Unknown flags: %s", unknown))
    }
}
