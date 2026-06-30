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
        if pin, _, _, err := pda.crack(); err == nil {
            pda.foundMode = rt
            pda.pin = pin
            return true
        }
    }

    // ES1 = ES2 = E-Nonce
    pda.eSecret1 = append([]byte(nil), pda.eNonce...)
    pda.eSecret2 = append([]byte(nil), pda.eNonce...)
    if pin, _, _, err := pda.crack(); err == nil {
        pda.foundMode = rtl819x
        pda.pin = pin
        return true
    }

    return false
}