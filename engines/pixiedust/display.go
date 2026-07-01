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
	"offscan/internal/utils"
	"os"
	"strconv"
	"strings"
	"time"
)



func (pda *pixieDustAttack) displayModes() {
	var modes []string

	for m := range pda.modes {
		modes = append(modes, strconv.Itoa(m))
	}

	fmt.Printf("[i] MODES..: %s", strings.Join(modes, ", "))
}



func (pda *pixieDustAttack) displayTime() {
	elapsed := time.Since(pda.timeExec).Seconds()
    fmt.Printf("[t] %.2f seconds in execution\n", elapsed)
}



func (pda *pixieDustAttack) displayPIN() {
    if pda.firstHalf == -1 && pda.secondHalf == -1 {
        fmt.Println("[!] PIN not found")
        os.Exit(0)

    }

    if pda.emptyPin {
        fmt.Println("[*] Empty PIN")
        os.Exit(0)
    }

    pin := utils.Pick(pda.firstHalf > -1,  fmt.Sprintf("%d", pda.firstHalf),  "????")
    pin += utils.Pick(pda.secondHalf > -1, fmt.Sprintf("%d", pda.secondHalf), "????")

    if !pda.pinFound() {
        fmt.Println("[!] Only the first half was found")
    }

    fmt.Printf("[*] PIN: %s", pin)
    os.Exit(0)
}