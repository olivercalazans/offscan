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
	"offscan/internal/utils"
	"time"
)



func (pda *pixieDustAttack) validDHSmallFlag() {
    if pda.dhSmall && pda.pkr != nil {
        utils.Abort("Options -S/--dhsmall and -r/--pkr are mutually exclusive")
    }

    if !pda.dhSmall && pda.pkr == nil {
        utils.Abort("Either -S/--dhsmall or -r/--pkr must be specified")
    }
}



func (pda *pixieDustAttack) validRequiredFlags() {
	b1 := pda.pke == nil || pda.eHash1 == nil || pda.eHash2 == nil || pda.eNonce == nil
	b2 := pda.dhSmall || pda.isRTL819x
	b3 := pda.ebssid != nil && pda.rNonce != nil
	
	miss := b1 || (pda.authKey == nil && !(b2 && b3))

	if miss {
		utils.Abort("Not all required arguments have been supplied")
	}
}



func (pda *pixieDustAttack) validDates() {
	if pda.force && (pda.start != -1 || pda.end != -1) {
		utils.Abort("Cannot specify --start or --end with --force")
	}
}



func (pda *pixieDustAttack) setTimeRange() {
    if !pda.isModeSelect(rtl819x) { return }

	startArg := pda.start
	endArg   := pda.end

    now := time.Now().Unix()
    pda.start = now + secPerDay
    pda.end = now - secPerDay

    if startArg != -1 {
        if endArg != -1 {
            if startArg == endArg {
                utils.Abort("Starting and ending points must be different")
            }
            if endArg > startArg {
                pda.start = endArg
                pda.end   = startArg
            } else {
                pda.start = startArg
                pda.end   = endArg
            }

        } else {
            if startArg >= pda.start {
                utils.Abort("Bad starting point")
            }
            
			pda.end = startArg
        }

    } else {
        if endArg != -1 {
            if endArg >= pda.start {
                utils.Abort("Bad ending point")
            }
            
			pda.end = endArg
    
		} else {
            if pda.force {
                pda.start += secPerDay
                pda.end    = 0
            }
        }
    }
}



func (pda *pixieDustAttack) setSmallKeys() {
	if pda.pkr != nil && pda.checkSmallDHKeys() {
		pda.dhSmall = true
	}
}