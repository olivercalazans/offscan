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


func (pda *pixieDustAttack) memAllocEHash1() {
    pda.eHash1 = make([]byte, wpsHashLen)
}


func (pda *pixieDustAttack) memAllocEHash2() {
    pda.eHash2 = make([]byte, wpsHashLen)
}


func (pda *pixieDustAttack) memAllocPKE() {
    pda.pke = make([]byte, wpsPkeyLen)
}


func (pda *pixieDustAttack) memAllocPKR() {
    pda.pkr = make([]byte, wpsPkeyLen)
}


func (pda *pixieDustAttack) memAllocENonce() {
    pda.eNonce = make([]byte, wpsNonceLen)
}


func (pda *pixieDustAttack) memAllocRNonce() {
    pda.rNonce = make([]byte, wpsNonceLen)
}


func (pda *pixieDustAttack) memAllocEbssid() {
    pda.ebssid = make([]byte, wpsBssidLen)
}


func (pda *pixieDustAttack) memAllocESecret1() {
    pda.eSecret1 = make([]byte, wpsSecretNonceLen)
}


func (pda *pixieDustAttack) memAllocESecret2() {
    pda.eSecret2 = make([]byte, wpsSecretNonceLen)
}


func (pda *pixieDustAttack) memAllocPSK1() {
    pda.psk1 = make([]byte, wpsHashLen)
}


func (pda *pixieDustAttack) memAllocPSK2() {
    pda.psk2 = make([]byte, wpsHashLen)
}


func (pda *pixieDustAttack) memAllocEmptyPSK() {
    pda.emptyPsk = make([]byte, wpsHashLen)
}


func (pda *pixieDustAttack) memAllocDHKey() {
    pda.dhKey = make([]byte, wpsHashLen)
}


func (pda *pixieDustAttack) memAllocKDK() {
    pda.kdk = make([]byte, wpsHashLen)
}


func (pda *pixieDustAttack) memAllocAuthKey() {
    pda.authKey = make([]byte, wpsAuthkeyLen)
}


func (pda *pixieDustAttack) memAllocWrapKey() {
    pda.wrapKey = make([]byte, wpsKeywrapkeyLen)
}


func (pda *pixieDustAttack) memAllocEMSK() {
    pda.emsk = make([]byte, wpsEmskLen)
}


func (pda *pixieDustAttack) memAllocM5() {
    pda.m5encr = make([]byte, encSettingsLen)
}


func (pda *pixieDustAttack) memAllocM7() {
    pda.m7encr = make([]byte, encSettingsLen)
}