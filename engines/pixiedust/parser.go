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
	"encoding/hex"
	"fmt"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/utils"
	"runtime"
	"slices"
	"strconv"
	"strings"
)


const (
	jobs    = 1
	pke     = 2
	pkr     = 3
	eHash1  = 4
	eHash2  = 5
	authKey = 6
	eNonce  = 7
	rNonce  = 8
	ebssid  = 9
	modes   = 10
	force   = 11
	dhSmall = 12
	m5enc   = 13
	m7enc   = 14
	start   = 15
	end     = 16
	cStart  = 17
	cEnd    = 18
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: "Pixie Dust\nE.g., $ sudo ./offscan pixie <FLAGS>"},	
		{ID: jobs,    Short: "j", Long: "jobs",    HasValue: true, Desc: "Number of workers"},
		{ID: pke ,    Short: "e", Long: "pke",     HasValue: true, Desc: "Public Key Enrollee"},
		{ID: pkr ,    Short: "r", Long: "pkr",     HasValue: true, Desc: "Public Key Registrar"},
		{ID: eHash1,  Short: "1", Long: "ehash1",  HasValue: true, Desc: "Enrollee Hash 1"},
		{ID: eHash2,  Short: "2", Long: "ehash2",  HasValue: true, Desc: "Enrollee Hash 2"},
		{ID: authKey, Short: "a", Long: "authkey", HasValue: true, Desc: "Authentication Session Key"},
		{ID: eNonce,  Short: "n", Long: "enonce",  HasValue: true, Desc: "Enrollee Nonce"},
		{ID: rNonce,  Short: "m", Long: "rnonce",  HasValue: true, Desc: "Registrar Nonce"},
		{ID: ebssid,  Short: "b", Long: "ebssid",  HasValue: true, Desc: "Enrollee MAC"},
		{ID: m5enc,   Short: "5", Long: "m5enc",   HasValue: true, Desc: "DH Small"},
		{ID: m7enc,   Short: "7", Long: "m7enc",   HasValue: true, Desc: "DH Small"},
		{ID: force,   Short: "f", Long: "force",   Desc: "Force bruteforce"},
		{ID: dhSmall, Short: "S", Long: "dhsmall", Desc: "Use small DH group"},
		{ID: modes,   Long: "mode",   HasValue: true, Desc: "Attack mode (1-5, 0=auto)"},
		{ID: start,   Long: "start",  HasValue: true, Desc: "Start timestamp for mode 3"},
		{ID: end,     Long: "end",    HasValue: true, Desc: "End timestamp for mode 3"},
		{ID: cStart,  Long: "cstart", HasValue: true, Desc: "Custom start seed"},
		{ID: cEnd,    Long: "cend",   HasValue: true, Desc: "Custom end seed"},
	}
}



func (pda *pixieDustAttack) parseArgs(args []string) {
	pda.setStatic()

    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case jobs    : pda.setJobs(flag.ValueStr)
		case pke     : strToHex(&flag, pda.pke, wpsPkeyLen)
		case pkr     : strToHex(&flag, pda.pkr, wpsPkeyLen)
		case eHash1  : strToHex(&flag, pda.eHash1, wpsHashLen)
		case eHash2  : strToHex(&flag, pda.eHash2, wpsHashLen)
		case authKey : strToHex(&flag, pda.authKey, wpsHashLen)
		case eNonce  : strToHex(&flag, pda.eNonce, wpsNonceLen)
		case rNonce  : strToHex(&flag, pda.rNonce, wpsNonceLen)
		case ebssid  : strToHex(&flag, pda.ebssid, wpsBssidLen)
		case modes   : pda.validateModes(flag.ValueStr)
		case m5enc   : hexStrToByteSliceMax(&flag, pda.m5enc, encSettingsLen)
		case m7enc   : hexStrToByteSliceMax(&flag, pda.m7enc, encSettingsLen)
		case force   : pda.force   = flag.ValueBool
		case dhSmall : pda.dhSmall = flag.ValueBool
		case start   : pda.start   = flag.ValueStr
		case end     : pda.end     = flag.ValueStr
		case cStart  : pda.cStart  = conv.StrToInt(flag.ValueStr)
		case cEnd    : pda.cEnd    = conv.StrToInt(flag.ValueStr)
		}
	}
}



func (pda *pixieDustAttack) setStatic() {
	pda.firstHalf  = -1
	pda.secondHalf = -1
}



func (pda *pixieDustAttack) setJobs(str string) {
	if str == "" {
		pda.jobs = getCoresNum()
	}

	num := conv.StrToInt(str)
    if num < 0 {
        utils.Abort(fmt.Sprintf("Bad number of jobs: %s", str))
    }

    pda.jobs = num
}



func getCoresNum() int {
	cores := runtime.NumCPU()	
	return utils.Pick(cores <= 0, 1, cores)
}



func strToHex(flag *argparser.Flag, buf []byte, mustLen int) {
	if flag.ValueStr == "" { return }

	err := hexStrToByteSlice(flag.ValueStr, buf, mustLen)
	
	if err == nil {
		flagName := argparser.GetInlineFlags(flag)
		utils.Abort(fmt.Sprintf("%s %v", flagName, err))
	}
}



func hexStrToByteSlice(str string, buf []byte, mustLen int) error {
    clean := removeSeparetors(str)

    if len(clean) != mustLen * 2 {
        return fmt.Errorf("Invalid length: expected %d hex chars, got %d", mustLen*2, len(clean))
    }

    _, err := hex.Decode(buf, []byte(clean))
    return err
}



func removeSeparetors(str string) string {
	return strings.Map(func(r rune) rune {
        if r == ':' || r == '-' || r == ' ' {
            return -1 
        }
        return r
    }, str)
}



func hexStrToByteSliceMax(flag *argparser.Flag, buf []byte, maxLen int) {
	if flag.ValueStr == "" { return }

    clean := removeSeparetors(flag.ValueStr)

    if len(clean)%2 != 0 {
        utils.Abort("Odd length hex string")
    }

    byteLen := len(clean) / 2
    if byteLen > maxLen {
        utils.Abort(fmt.Sprintf("Hex string too long: max %d bytes, got %d", maxLen, byteLen))
    }

    buf = make([]byte, byteLen)
    if _, err := hex.Decode(buf, []byte(clean)); err != nil {
        utils.Abort(fmt.Sprintf("Invalid hex string: %v", err))
    }
}



func (pda *pixieDustAttack) validateModes(str string) {
	modesStr := strings.Split(str, ",")
	len      := len(modesStr)

	if len <= 0 {
		pda.modes = []uint8{}
	}

	if len > 5 {
		utils.Abort("More than 5 modes selected")
	}

	for _, s := range modesStr {
		mode, err := strconv.ParseInt(s, 10, 8)

		if err != nil {
			utils.Abort(fmt.Sprintf("Bad char for mode: %s", s))
		}
		
		if mode > 5 || mode < 0 {
			utils.Abort(fmt.Sprintf("Bad number for mode: %s. Use 0-5 for modes", s))
		}

		modeU8 := uint8(mode)

		if slices.Contains(pda.modes, modeU8) {
			utils.Abort(fmt.Sprintf("Duplicated number mode: %s", s))
		}
		
		pda.modes = append(pda.modes, modeU8)
	}
}



func (pda *pixieDustAttack) validDHSmallFlag() {
    if pda.dhSmall && pda.pkr != nil {
        utils.Abort("Options -S/--dhsmall and -r/--pkr are mutually exclusive")
    }

    if !pda.dhSmall && pda.pkr == nil {
        utils.Abort("Either -S/--dhsmall or -r/--pkr must be specified")
    }
}



func (pda *pixieDustAttack) validRequiredFlags() {
	b1 := pda.pke == nil || pda.eHash1 == nil || pda.eHash2 == nil || pda.eNonce == nil
	b2 := pda.dhSmall || pda.isRTL819xPKE()
	b3 := pda.ebssid != nil && pda.rNonce != nil
	
	miss := b1 || (pda.authKey == nil && !(b2 && b3))

	if miss {
		utils.Abort("Not all required arguments have been supplied")
	}
}