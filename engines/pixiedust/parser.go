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
	"time"
)


func DisplayHelp() {
	help := "\n# Pixie Dust. E.g., $ sudo ./offscan pixie <FLAGS>\n\n" +
	        "    -1, --ehash1 <HASH>  : (Required) Enrollee Hash 1\n" +
	        "    -2, --ehash2 <HASH>  : (Required) Enrollee Hash 2\n" +
	        "    -e, --pke <HASH>     : (Required) Public Key Enrollee\n" +
	        "    -r, --pkr <HASH>     : (Optional) Public Key Registrar\n" +
	        "    -a, --authkey <KEY>  : (Optional) Authentication Session Key\n" +
	        "    -n, --enonce <HASH>  : (Optional) Enrollee Nonce\n" +
	        "    -m, --rnonce <HASH>  : (Optional) Registrar Nonce\n" +
	        "    -b, --ebssid <BSSID> : (Optional) Enrollee MAC\n" +
	        "        --mode <INT>     : (Optional) Attack mode (1-5, 0=auto)\n" +
	        "    -j, --jobs <INT>     : (Optional) Number of workers\n" +
	        "    -f, --force          : (Optional) Force bruteforce\n" +
	        "    -S, --small          : (Optional) Use small DH group\n" +
	        "    -5, --m5enc <HASH>   : (Mode 3)   Recover secret nonce from M5\n" +
	        "    -7, --m7enc <HASH>   : (Mode 3)   Recover encrypted settings froLm M7\n" +
	        "        --start <DATE>   : (Optional) Start timestamp for mode 3\n" +
	        "        --end <DATE>     : (Optional) End timestamp for mode 3\n" +
	        "        --cstart <HASH>  : (Optional) Custom start seed\n" +
	        "        --cend <HASH>    : (Optional) Custom end seed\n"

		fmt.Println(help)
}



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
		{ID: jobs,    Short: "j", Long: "jobs",    HasValue: true},
		{ID: pke ,    Short: "e", Long: "pke",     HasValue: true},
		{ID: pkr ,    Short: "r", Long: "pkr",     HasValue: true},
		{ID: eHash1,  Short: "1", Long: "ehash1",  HasValue: true},
		{ID: eHash2,  Short: "2", Long: "ehash2",  HasValue: true},
		{ID: authKey, Short: "a", Long: "authkey", HasValue: true},
		{ID: eNonce,  Short: "n", Long: "enonce",  HasValue: true},
		{ID: rNonce,  Short: "m", Long: "rnonce",  HasValue: true},
		{ID: ebssid,  Short: "b", Long: "ebssid",  HasValue: true},
		{ID: m5enc,   Short: "5", Long: "m5enc",   HasValue: true},
		{ID: m7enc,   Short: "7", Long: "m7enc",   HasValue: true},
		{ID: force,   Short: "f", Long: "force"},
		{ID: dhSmall, Short: "S", Long: "dhsmall"},
		{ID: modes,   Long: "mode",   HasValue: true},
		{ID: start,   Long: "start",  HasValue: true},
		{ID: end,     Long: "end",    HasValue: true},
		{ID: cStart,  Long: "cstart", HasValue: true},
		{ID: cEnd,    Long: "cend",   HasValue: true},
	}
}



func (pda *pixieDustAttack) parseArgs(args []string) {
	pda.setStatic()

    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)
	args = nil


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
		case start   : pda.start   = parseDate(flag.ValueStr)
		case end     : pda.end     = parseDate(flag.ValueStr)
		case cStart  : pda.cStart  = conv.StrToInt(flag.ValueStr)
		case cEnd    : pda.cEnd    = conv.StrToInt(flag.ValueStr)
		}
	}
}



func (pda *pixieDustAttack) setStatic() {
	pda.firstHalf  = -1
	pda.secondHalf = -1
	pda.modes      = make([]uint8, 0)
	pda.dhKey      = make([]byte, 0)
	pda.psk1       = make([]byte, 0)
	pda.psk2       = make([]byte, 0)
	pda.eSecret1   = make([]byte, 0)
	pda.eSecret2   = make([]byte, 0)
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



func parseDate(str string) int64 {
	if str == "" { return -1 }
	date := conv.MustStrToInt(str)
	return int64(date)
}



func (pda *pixieDustAttack) validateModes(str string) {
	if str == "" {
		pda.auto  = true
		pda.modes = []uint8{}
		return
	}

	modesStr := strings.Split(str, ",")
	len      := len(modesStr)

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
	b2 := pda.dhSmall || pda.isRTL819x
	b3 := pda.ebssid != nil && pda.rNonce != nil
	
	miss := b1 || (pda.authKey == nil && !(b2 && b3))

	if miss {
		utils.Abort("Not all required arguments have been supplied")
	}
}



func (pda *pixieDustAttack) validDates() {
	if pda.force && (pda.start != -1 || pda.end != -1) {
		utils.Abort("Cannot specify --start or --end with --force")
	}
}



func (pda *pixieDustAttack) setTimeRange() {
    if !pda.isModeSelect(rtl819x) { return }

	startArg := pda.start
	endArg   := pda.end

    now := time.Now().Unix()
    pda.start = now + secPerDay
    pda.end = now - secPerDay

    if startArg != -1 {
        if endArg != -1 {
            if startArg == endArg {
                utils.Abort("Starting and ending points must be different")
            }
            if endArg > startArg {
                pda.start = endArg
                pda.end   = startArg
            } else {
                pda.start = startArg
                pda.end   = endArg
            }

        } else {
            if startArg >= pda.start {
                utils.Abort("Bad starting point")
            }
            
			pda.end = startArg
        }

    } else {
        if endArg != -1 {
            if endArg >= pda.start {
                utils.Abort("Bad ending point")
            }
            
			pda.end = endArg
    
		} else {
            if pda.force {
                pda.start += secPerDay
                pda.end    = 0
            }
        }
    }
}