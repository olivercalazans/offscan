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

package generators

import (
	"fmt"
	"math/rand"
	"offscan/internal/utils"
	"strconv"
	"strings"
	"time"
)



type DelayMode struct {
    Fixed bool   
    Value float64
    Min   float64
    Max   float64
}



type DelayIter struct {
    mode        DelayMode
    remaining   int
    rng        *rand.Rand
}



func NewDelayIter(delayArg string, quantity int) *DelayIter {
    var mode DelayMode

    if strings.Contains(delayArg, "-") {
        parts := strings.SplitN(delayArg, "-", 2)

		if len(parts) != 2 {
            utils.Abort(fmt.Sprintf("Invalid delay range: %s", delayArg))
        }

        min := validateNumber(parts[0])
        max := validateNumber(parts[1])

        if min >= max {
            utils.Abort(fmt.Sprintf("Invalid delay range: %s (min >= max)", delayArg))
        }

        mode = DelayMode{
            Fixed: false,
            Min:   min,
            Max:   max,
        }
    } else {
        value := validateNumber(delayArg)
        mode   = DelayMode{
            Fixed: true,
            Value: value,
        }
    }

    var rng *rand.Rand
    if !mode.Fixed {
        src := rand.NewSource(time.Now().UnixNano())
        rng  = rand.New(src)
    }

    return &DelayIter{
        mode:      mode,
        remaining: quantity,
        rng:       rng,
    }
}



func validateNumber(s string) float64 {
    val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Invalid number: %s", s))
    }

    return val
}



func (di *DelayIter) Next() (float64, bool) {
    if di.remaining <= 0 {
        return 0, false
    }
    
	di.remaining--

    if di.mode.Fixed {
        return di.mode.Value, true
    }

    delta := di.mode.Max - di.mode.Min
    val   := di.mode.Min + di.rng.Float64()*delta

    return val, true
}