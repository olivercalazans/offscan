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
	"offscan/internal/conv"
	"runtime"
	"slices"
	"strconv"
	"strings"
)



func getCoresNum() int {
	cores := runtime.NumCPU()
	if cores <= 0 { cores = 1 }
	return cores
}



func strToHex(str string, mustLen int) ([]byte, error) {
    if str == "" {
		return nil, fmt.Errorf("Empty value")
    }
    
	buf := make([]byte, mustLen)
    err := hexStrToByteSlice(str, buf, mustLen)
    
	if err != nil {
        return nil, err
    }
    
	return buf, nil
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



func hexStrToByteSliceMax(str string, maxLen int) ([]byte, error) {
    if str == "" {
        return nil, fmt.Errorf("Empty value")
    }
    
	clean := removeSeparetors(str)
    if len(clean)%2 != 0 {
        return nil, fmt.Errorf("Odd length hex string")
    }
    
	byteLen := len(clean) / 2
    if byteLen > maxLen {
        return nil, fmt.Errorf("Hex string too long: max %d bytes, got %d", maxLen, byteLen)
    }
    
	buf := make([]byte, byteLen)
    if _, err := hex.Decode(buf, []byte(clean)); err != nil {
        return nil, fmt.Errorf("Invalid hex string: %v", err)
    }
    
	return buf, nil
}



func parseDate(str string) int64 {
	if str == "" { return -1 }
	date := conv.MustStrToInt(str)
	return int64(date)
}



func validateModes(str string) ([]uint8, error) {
	modes := make([]uint8, 0)

	modesStr := strings.Split(str, ",")
	len      := len(modesStr)

	if len > 5 {
		return nil, fmt.Errorf("More than 5 modes selected")
	}

	for _, s := range modesStr {
		mode, err := strconv.ParseInt(s, 10, 8)

		if err != nil {
			return nil, fmt.Errorf("Bad char for mode: %s", s)
		}
		
		if mode > 5 || mode < 0 {
			return nil, fmt.Errorf("Bad number for mode: %s. Use 0-5 for modes", s)
		}

		modeU8 := uint8(mode)

		if slices.Contains(modes, modeU8) {
			return nil, fmt.Errorf("Duplicated number mode: %s", s)
		}
		
		modes = append(modes, modeU8)
	}

	return modes, nil
}