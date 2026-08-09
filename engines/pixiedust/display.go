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

package pixiedust

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)



func (pda *pixieDustAttack) displayModes() {
	var modes []string

	for _, m := range pda.modes {
		modes = append(modes, strconv.Itoa(int(m)))
	}

	fmt.Printf("[i] MODES..: %s\n", strings.Join(modes, ", "))
}



func (pda *pixieDustAttack) displayTime() {
	elapsed := time.Since(pda.timeExec).Seconds()
    fmt.Printf("[t] %.2f seconds in execution\n", elapsed)
}



func (pda *pixieDustAttack) displayPIN() {
    if pda.firstHalf == -1 && pda.secondHalf == -1 {
        pda.displayTime()
        fmt.Printf("\n[!] PIN not found\n\n")
        os.Exit(0)
    }

    if pda.emptyPin {
        pda.displayTime()
        fmt.Printf("\n[*] Empty PIN\n\n")
        os.Exit(0)
    }

    var pin string

    if pda.firstHalf  > -1 { pin += fmt.Sprintf("%d", pda.firstHalf)  } else { pin += "????" }
    if pda.secondHalf > -1 { pin += fmt.Sprintf("%d", pda.secondHalf) } else { pin += "????" }

    if !pda.pinFound() {
        fmt.Println("[!] Only the first half was found")
    }

    pda.displayTime()

    fmt.Printf("\n[*] PIN: %s\n\n", pin)
    os.Exit(0)
}