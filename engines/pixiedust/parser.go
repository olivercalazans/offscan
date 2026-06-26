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



func (pda *pixieDustAttack) parsePortScanArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case jobs    : pda.jobs    = getJobs(flag.ValueStr)
		case pke     : pda.pke     = mustStrToHex(flag.ValueStr)
		case pkr     : pda.pkr     = mustStrToHex(flag.ValueStr)
		case eHash1  : pda.eHash1  = mustStrToHex(flag.ValueStr)
		case eHash2  : pda.eHash2  = mustStrToHex(flag.ValueStr)
		case authKey : pda.authKey = mustStrToHex(flag.ValueStr)
		case eNonce  : pda.eNonce  = mustStrToHex(flag.ValueStr)
		case rNonce  : pda.rNonce  = strToHex(flag.ValueStr)
		case ebssid  : pda.ebssid  = conv.MustStrToMac(flag.ValueStr)
		case modes   : pda.modes   = validateModes(flag.ValueStr)
		case m5enc   : pda.m5enc   = strToHex(flag.ValueStr)
		case m7enc   : pda.m7enc   = strToHex(flag.ValueStr)
		case force   : pda.force   = flag.ValueBool
		case dhSmall : pda.dhSmall = flag.ValueBool
		case start   : pda.start   = flag.ValueStr
		case end     : pda.end     = flag.ValueStr
		case cStart  : pda.cStart  = conv.StrToInt(flag.ValueStr)
		case cEnd    : pda.cEnd    = conv.StrToInt(flag.ValueStr)
		}
	}
}



func getJobs(str string) int {
	if str == "" {
		return getCoresNum()
	}

	val := conv.StrToInt(str)
    if val <= 0 {
        return getCoresNum()
    }

    return val
}



func getCoresNum() int {
	cores := runtime.NumCPU()
		
	if cores <= 0 {
		return 1
	}

	return cores
}



func strToHex(str string) []byte {
	if str == "" {
		return []byte{}
	}

	hash, err := hex.DecodeString(str)
	
	if err == nil {
		utils.Abort(fmt.Sprintf("%v", err))
	}

	return hash
}



func mustStrToHex(str string) []byte {
	hash, err := hex.DecodeString(str)
	
	if err == nil {
		utils.Abort(fmt.Sprintf("%v", err))
	}

	return hash
}



func validateModes(str string) []uint8 {
	modesStr := strings.Split(str, ",")
	len   := len(modesStr)

	if len <= 0 {
		return []uint8{}
	}

	if len > 5 {
		utils.Abort("More than 5 modes selected")
	}

	var modesU8 []uint8
	for _, s := range modesStr {
		modesU8 = append(modesU8, []byte(s)...)
	}

	return modesU8
}