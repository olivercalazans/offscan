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
	"strings"
)


type CommandHandler struct {
	Run    func(args []string)
	Helper func()
}



func DisplayAllHelp(registry map[string]CommandHandler) {
	cmds := slices.Collect(maps.Keys(registry))
	sort.Strings(cmds)

	for _, cmd := range cmds {
		reg  := registry[cmd]
		help := reg.Helper
		help()
	}

	os.Exit(0)
}



func (ap *ArgParser) displayErrors() {
	if len(ap.errors) == 0 { return }

	fmt.Printf("[!] ERROR(S):\n")
	
	for _, e := range ap.errors {
		fmt.Printf("  %s\n", e)
	}

	fmt.Printf("\n")
}



func (ap *ArgParser) displayMissingFlags() {
	if len(ap.missingFlags) == 0 { return }

	fmt.Printf("[!] MISSING FLAG(S):\n")
	
	for _, e := range ap.missingFlags {
		fmt.Printf("  %s\n", e)
	}

	fmt.Printf("\n")
}



func (ap *ArgParser) displayMissingValues() {
	if len(ap.missingValues) == 0 { return }

	fmt.Printf("[!] MISSING VALUE(S) FOR FLAG(S):\n")
	
	for _, e := range ap.missingValues {
		fmt.Printf("  %s\n", e)
	}

	fmt.Printf("\n")
}



func (ap *ArgParser) displayDuplicated() {
	if len(ap.duplicated) == 0 { return }

	fmt.Printf("[!] DUPLICATED FLAGS:\n")
	
	for _, e := range ap.duplicated {
		fmt.Printf("  %s\n", e)
	}

	fmt.Printf("\n")
}



func (ap *ArgParser) displayRemainingArgs() {
	if len(ap.args) == 0 { return }

	fmt.Printf("[!] Unknown Flag(s):\n")
	fmt.Printf("  %s\n", strings.Join(ap.args, ", "))
	fmt.Printf("\n")
}