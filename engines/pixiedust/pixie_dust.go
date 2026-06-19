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
	"bytes"
	"fmt"
	"runtime"
	"slices"
	"time"
)



type pixieDustAttack struct {
	pke       []byte
    pkr       []byte
    eHash1    []byte
    eHash2    []byte
    authKey   []byte
    eNonce    []byte
    rNonce    []byte
    bssid     []byte    
    jobs      int
	modeAuto  bool
	modes     []uint8
}



func newPixieDust(args []string) pixieDustAttack {
	parser := pixieDustParser{}
	parser.parsePortScanArgs(args)

	return pixieDustAttack{
		jobs: runtime.NumCPU(),
	}
}



func (pda *pixieDustAttack) execute() {
	timeStart := time.Now()
	displayTime(timeStart)
}



func (pda *pixieDustAttack) isModeSelect(mode uint8) bool {
	return slices.Contains(pda.modes, mode)
}



func validatePKE(pke []byte) error {
    if !bytes.Equal(pke, wpsRtlPke) {
        return fmt.Errorf("Model not supported! (PKE does not match RTL819x)")
    }
    return nil
}



func displayTime(timeStart time.Time) {
	elapsed := time.Since(timeStart).Seconds()
    fmt.Printf("[%%] %.2f seconds in execution\n", elapsed)
}