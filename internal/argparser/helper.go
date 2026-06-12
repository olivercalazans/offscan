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
	"maps"
	"os"
	"slices"
	"sort"
)


type CommandHandler struct {
	Run          func(args []string)
	FlagSettings func() []Flag
}



func DisplayAllHelp(registry map[string]CommandHandler) {
	cmds := slices.Collect(maps.Keys(registry))
	sort.Strings(cmds)

	for _, cmd := range cmds {
		reg := registry[cmd]
		flags := reg.FlagSettings
		displayFlags(flags())
	}

	os.Exit(0)
}



func displayFlags(flagSettings []Flag) {
    sort.Slice(flagSettings, func(i, j int) bool {
        return flagSettings[i].ID < flagSettings[j].ID 
    })

	formatFlags(flagSettings)
    descLen := GetFlagMaxLen(flagSettings)

    for _, f := range flagSettings {
		if f.ID == 0 {
			fmt.Printf("\n## %s\nFlags:\n", f.Desc)
			continue
		}

        flags := GetInlineFlags(&f)
		req   := "(Optional)"
		
		if f.Req { req = "(Required)" }

        fmt.Printf("  %-*s : %s %s\n", descLen, flags, req, f.Desc)
    }

	fmt.Println("")
}



func formatFlags(flagSettings []Flag) {
    for i := range flagSettings {
        flag := &flagSettings[i]
        
        if flag.Short != "" { flag.Short = fmt.Sprintf("-%s", flag.Short) }
        if flag.Long  != "" { flag.Long  = fmt.Sprintf("--%s", flag.Long) }
    }
}



func GetFlagMaxLen(flagSettings []Flag) int {
    var maxLen int

    for _, f := range flagSettings {
        str := GetInlineFlags(&f)
        len := len(str)
        
        if len > maxLen { maxLen = len }
    }

    return maxLen
}