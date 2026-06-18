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
	"net"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/utils"
	"runtime"
)



type pixieDustParser struct {
	jobs     int
	pke      []byte
	pkr      []byte
	eHash1   []byte
	eHash2   []byte
	authKey  []byte
	eNonce   []byte
	rNonce   []byte
	ebssid   net.HardwareAddr
	mode     uint8
	force    bool
	dhSmall  bool
	start    string
	end      string
	cStart   int
	cEnd     int
}


const (
	jobs     uint8 = 1
	pke      uint8 = 2
	pkr      uint8 = 3
	eHash1   uint8 = 4
	eHash2   uint8 = 5
	authKey  uint8 = 6
	eNonce   uint8 = 7
	rNonce   uint8 = 8
	ebssid   uint8 = 9
	mode     uint8 = 10
	force    uint8 = 11
	dhSmall  uint8 = 12
	m5enc    uint8 = 13
	m7enc    uint8 = 14
	start    uint8 = 15
	end      uint8 = 16
	cStart   uint8 = 17
	cEnd     uint8 = 18
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: "Pixie Dust\nE.g., $ sudo ./offscan pixie <FLAGS>"},	
		{ID: jobs,    Short: "j", Long: "jobs",    HasValue: true, Desc: "Number of workers"},
		{ID: pke ,    Short: "e", Long: "pke",     HasValue: true, Req: true, Desc: "Public Key Enrollee"},
		{ID: pkr ,    Short: "r", Long: "pkr",     HasValue: true, Req: true, Desc: "Public Key Registrar"},
		{ID: eHash1,  Short: "1", Long: "ehash1",  HasValue: true, Req: true, Desc: "Enrollee Hash 1"},
		{ID: eHash2,  Short: "2", Long: "ehash2",  HasValue: true, Req: true, Desc: "Enrollee Hash 2"},
		{ID: authKey, Short: "a", Long: "authkey", HasValue: true, Req: true, Desc: "Authentication Session Key"},
		{ID: eNonce,  Short: "n", Long: "enonce",  HasValue: true, Req: true, Desc: "Enrollee Nonce"},
		{ID: rNonce,  Short: "m", Long: "rnonce",  HasValue: true, Desc: "Registrar Nonce"},
		{ID: ebssid,  Short: "b", Long: "ebssid",  HasValue: true, Desc: "Enrollee MAC"},
		{ID: m5enc,   Short: "5", Long: "m5enc",   HasValue: true, Desc: "DH Small"},
		{ID: m7enc,   Short: "7", Long: "m7enc",   HasValue: true, Desc: "DH Small"},
		{ID: force,   Short: "f", Long: "force",   Desc: "Force bruteforce"},
		{ID: dhSmall, Short: "S", Long: "dhsmall", Desc: "Use small DH group"},
		{ID: mode,    Long: "mode",   HasValue: true, Desc: "Attack mode (1-5, 0=auto)"},
		{ID: start,   Long: "start",  HasValue: true, Desc: "Start timestamp for mode 3"},
		{ID: end,     Long: "end",    HasValue: true, Desc: "End timestamp for mode 3"},
		{ID: cStart,  Long: "cstart", HasValue: true, Desc: "Custom start seed"},
		{ID: cEnd,    Long: "cend",   HasValue: true, Desc: "Custom end seed"},
	}
}



func (pdp *pixieDustParser) parsePortScanArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case jobs    : pdp.jobs    = getJobs(flag.ValueStr)
		case pke     : pdp.pke     = pdp.mustStrToHex(flag.ValueStr)
		case pkr     : pdp.pkr     = pdp.mustStrToHex(flag.ValueStr)
		case eHash1  : pdp.eHash1  = pdp.mustStrToHex(flag.ValueStr)
		case eHash2  : pdp.eHash2  = pdp.mustStrToHex(flag.ValueStr)
		case authKey : pdp.authKey = pdp.mustStrToHex(flag.ValueStr)
		case eNonce  : pdp.eNonce  = pdp.mustStrToHex(flag.ValueStr)
		case rNonce  : pdp.rNonce  = pdp.strToHex(flag.ValueStr)
		case ebssid  : pdp.ebssid  = conv.MustStrToMac(flag.ValueStr)
		case force   : pdp.force   = flag.ValueBool
		case dhSmall : pdp.dhSmall = flag.ValueBool
		case start   : pdp.start   = flag.ValueStr
		case end     : pdp.end     = flag.ValueStr
		case cStart  : pdp.cStart  = conv.StrToInt(flag.ValueStr)
		case cEnd    : pdp.cEnd    = conv.StrToInt(flag.ValueStr)
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



func (pdp *pixieDustParser) strToHex(str string) []byte {
	if str == "" {
		return []byte{}
	}

	hash, err := hex.DecodeString(str)
	
	if err == nil {
		utils.Abort(fmt.Sprintf("%v", err))
	}

	return hash
}



func (pdp *pixieDustParser) mustStrToHex(str string) []byte {
	hash, err := hex.DecodeString(str)
	
	if err == nil {
		utils.Abort(fmt.Sprintf("%v", err))
	}

	return hash
}