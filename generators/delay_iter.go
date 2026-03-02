package generators

import (
	"fmt"
	"math/rand"
	"offscan/utils"
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