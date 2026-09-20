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
	"fmt"
	"offscan/internal/argparser"
)


func DisplayHelp() {
	help := "\n### PIXIE DUST\n\n" + 
			"    E.g., $ sudo ./offscan pixie <FLAGS>\n\n" +
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



func (pda *pixieDustAttack) parseArgs(args []string) {
	pda.setStatic()
	pdp := pixieDustParser{}

	pdp.engine = pda
	pdp.parser = argparser.NewArgParser(args)

	pdp.parsePKE()
	pdp.parsePKR()
	pdp.parseEHash1()
	pdp.parseEHash2()
	pdp.parseAuthKey()
	pdp.parseENonce()
	pdp.parseRNonce()
	pdp.parseEBSSID()
	pdp.parseM5Encr()
	pdp.parseM7Encr()
	pdp.parseJobs()
	pdp.parseModes()
	pdp.parseForce()
	pdp.parseDHSmall()
	pdp.parseStartDate()
	pdp.parseEndDate()
	pdp.parseCStartDate()
	pdp.parseCEndDate()
	
	pdp.parser.AbortIfHasError()
}



func (pda *pixieDustAttack) setStatic() {
	pda.firstHalf  = -1
	pda.secondHalf = -1
	pda.start      = -1
	pda.end        = -1
}



type pixieDustParser struct {
	engine  *pixieDustAttack
	parser  *argparser.ArgParser
}



func (pdp *pixieDustParser) parserHex(arg *argparser.Argument, lenHex int) ([]byte, bool) {
	str, ok := pdp.parser.String(arg)

	if !ok { return nil, true }

	hex, err := strToHex(str, lenHex)
	
	if err != nil {
		pdp.parser.AddError(arg, err)
		return nil, false
	}

	return hex, true
}



func (pdp *pixieDustParser) parsePKE() {
	arg := argparser.Argument{ Long: "--pke", Short: "-e", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsPkeyLen); ok {
		pdp.engine.memAllocPKE()
		pdp.engine.pke = hex
	}
}



func (pdp *pixieDustParser) parsePKR() {
	arg := argparser.Argument{ Long: "--pkr", Short: "-r", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsPkeyLen); ok {
		pdp.engine.memAllocPKR()
		pdp.engine.pkr = hex
	}
}



func (pdp *pixieDustParser) parseEHash1() {
	arg := argparser.Argument{ Long: "--ehash1", Short: "-1", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsHashLen); ok {
		pdp.engine.memAllocEHash1()
		pdp.engine.eHash1 = hex
	}
}



func (pdp *pixieDustParser) parseEHash2() {
	arg := argparser.Argument{ Long: "--ehash2", Short: "-2", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsHashLen); ok {
		pdp.engine.memAllocEHash2()
		pdp.engine.eHash2 = hex
	}
}



func (pdp *pixieDustParser) parseAuthKey() {
	arg := argparser.Argument{ Long: "--authkey", Short: "-a", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsHashLen); ok {
		pdp.engine.memAllocAuthKey()
		pdp.engine.authKey = hex
	}
}



func (pdp *pixieDustParser) parseENonce() {
	arg := argparser.Argument{ Long: "--enonce", Short: "-n", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsNonceLen); ok {
		pdp.engine.memAllocENonce()
		pdp.engine.eNonce = hex
	}
}



func (pdp *pixieDustParser) parseRNonce() {
	arg := argparser.Argument{ Long: "--rnonce", Short: "-m", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsNonceLen); ok {
		pdp.engine.memAllocRNonce()
		pdp.engine.rNonce = hex
	}
}



func (pdp *pixieDustParser) parseEBSSID() {
	arg := argparser.Argument{ Long: "--ebssid", Short: "-b", Required: false }

	if hex, ok := pdp.parserHex(&arg, wpsBssidLen); ok {
		pdp.engine.memAllocEbssid()
		pdp.engine.ebssid = hex
	}
}



func (pdp *pixieDustParser) parseM5Encr() {
	arg := argparser.Argument{ Long: "--m5enc", Short: "-5", Required: false }

	str, ok := pdp.parser.String(&arg)

	if !ok { return }

	hex, err := hexStrToByteSliceMax(str, wpsBssidLen)
	
	if err != nil {
		pdp.parser.AddError(&arg, err)
		return
	}

	pdp.engine.memAllocM5()
	pdp.engine.m5encr = hex
}



func (pdp *pixieDustParser) parseM7Encr() {
	arg := argparser.Argument{ Long: "--m7enc", Short: "-7", Required: false }

	str, ok := pdp.parser.String(&arg)

	if !ok { return }

	hex, err := hexStrToByteSliceMax(str, wpsBssidLen)
	
	if err != nil {
		pdp.parser.AddError(&arg, err)
		return
	}

	pdp.engine.memAllocM7()
	pdp.engine.m7encr = hex
}



func (pdp *pixieDustParser) parseJobs() {
	arg := argparser.Argument{ Long: "--jobs", Short: "-7", Required: false }

	i, ok := pdp.parser.Int(&arg)

	if !ok { 
		pdp.engine.jobs = getCoresNum()
	}

	if i < 0 {
		pdp.parser.AddError(&arg, fmt.Errorf("Bad number of jobs: %d", i))
		return
	}
}



func (pdp *pixieDustParser) parseModes() {
	arg := argparser.Argument{ Long: "--modes", Short: "", Required: false }

	str, ok := pdp.parser.String(&arg)

	if !ok {
		pdp.engine.auto  = true
		pdp.engine.modes = []uint8{}
		return
	}

	modes, err := validateModes(str)

	if err != nil {
		pdp.parser.AddError(&arg, err)
		return
	}

	pdp.engine.modes = modes
}



func (pdp *pixieDustParser) parseForce() {
	arg := argparser.Argument{ Long: "--force", Short: "-f", Required: false }
	pdp.engine.force = pdp.parser.Bool(&arg)
}



func (pdp *pixieDustParser) parseDHSmall() {
	arg := argparser.Argument{ Long: "--dhsmall", Short: "-S", Required: false }
	pdp.engine.dhSmall = pdp.parser.Bool(&arg)
}



func (pdp *pixieDustParser) parseStartDate() {
	arg := argparser.Argument{ Long: "--start", Short: "", Required: false }

	str, _ := pdp.parser.String(&arg)

	pdp.engine.start = parseDate(str)
}



func (pdp *pixieDustParser) parseEndDate() {
	arg := argparser.Argument{ Long: "--end", Short: "", Required: false }

	str, _ := pdp.parser.String(&arg)

	pdp.engine.end = parseDate(str)
}



func (pdp *pixieDustParser) parseCStartDate() {
	arg := argparser.Argument{ Long: "--cstart", Short: "", Required: false }

	i, _ := pdp.parser.Int(&arg)

	pdp.engine.cStart = i
}



func (pdp *pixieDustParser) parseCEndDate() {
	arg := argparser.Argument{ Long: "--cend", Short: "", Required: false }

	i, _ := pdp.parser.Int(&arg)

	pdp.engine.cEnd = i
}