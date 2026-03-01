package generators

import (
	"math"
	"math/rand"
	"net"
	"time"
)



type RandomValues struct {
    rng     *rand.Rand
    firstIP uint32
    lastIP  uint32
}



func NewRandomValues(firstIP, lastIP *uint32) *RandomValues {
    var f, l uint32

	if firstIP != nil {
        f = *firstIP
    }

	if lastIP != nil {
        l = *lastIP
    }

	src := rand.NewSource(time.Now().UnixNano())

	return &RandomValues{
        rng:     rand.New(src),
        firstIP: f,
        lastIP:  l,
    }
}



func (rv *RandomValues) RandomPort() uint16 {
    const minPort = 49152
    const maxPort = 65535
    return uint16(minPort + rv.rng.Intn(maxPort-minPort+1))
}



func (rv *RandomValues) RandomIP() net.IP {
    if rv.firstIP == 0 && rv.lastIP == 0 {
        return net.IPv4(0, 0, 0, 0)
    }

	rangeSize := rv.lastIP - rv.firstIP + 1
    randNum   := rv.firstIP + uint32(rv.rng.Int63n(int64(rangeSize)))

	return net.IPv4(
        byte(randNum>>24),
        byte(randNum>>16),
        byte(randNum>>8),
        byte(randNum),
    )
}



func (rv *RandomValues) randomU8Array() [6]byte {
    var bytes [6]byte
    rv.rng.Read(bytes[:])
    bytes[0] = (bytes[0] | 0x02) & 0xFE
    return bytes
}



func (rv *RandomValues) RandomMac() net.HardwareAddr {
	arr := rv.randomU8Array()
    return net.HardwareAddr(arr[:])
}



func (rv *RandomValues) RandomSeq() uint16 {
    return uint16(1 + rv.rng.Intn(4094))
}



func (rv *RandomValues) RandomCaseInversion(input string) string {
    if input == "" {
        return ""
    }

    chars      := []rune(input)
    totalChars := len(chars)

    changeCount := rv.determineChangeCount(totalChars)
    if changeCount == 0 {
        return input
    }

    letterIndices := make([]int, 0, totalChars)
    for i, c := range chars {
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
            letterIndices = append(letterIndices, i)
        }
    }

    if len(letterIndices) == 0 {
        return input
    }


	selected := make([]int, changeCount)

	if len(letterIndices) <= changeCount {
        selected = letterIndices
    } else {
        shuffled := make([]int, len(letterIndices))
        copy(shuffled, letterIndices)
        rv.rng.Shuffle(len(shuffled), func(i, j int) {
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        })
        selected = shuffled[:changeCount]
    }

    return invertCaseAtIndices(chars, selected)
}



func (rv *RandomValues) determineChangeCount(totalChars int) int {
    switch {
    case totalChars == 0:
        return 0

	case totalChars <= 3:
        if rv.rng.Float64() < 0.5 {
            return 1
        }
        return 0

	case totalChars <= 7:
        return rv.rng.Intn(2) + 1

	case totalChars <= 15:
        max := 4
        if half := totalChars / 2; half < max {
            max = half
        }
        return rv.rng.Intn(max-1) + 2

	case totalChars <= 31:
        sqrtBased := int(math.Ceil(math.Sqrt(float64(totalChars))))
        max       := sqrtBased

		if third := totalChars / 3; third < max {
            max = third
        }

		return rv.rng.Intn(max-2) + 3

	default:
        logBased     := int(math.Ceil(math.Log2(float64(totalChars))))
        percentBased := totalChars / 10
        maxChanges   := logBased

		if percentBased > maxChanges {
            maxChanges = percentBased
        }

		if quarter := totalChars / 4; quarter < maxChanges {
            maxChanges = quarter
        }

		return rv.rng.Intn(maxChanges-4) + 5
    }
}



func invertCaseAtIndices(chars []rune, indices []int) string {
    result := make([]rune, len(chars))
    copy(result, chars)
 
	for _, idx := range indices {
        c := chars[idx]
        
		switch {
        case c >= 'a' && c <= 'z': result[idx] = c - 'a' + 'A'
        case c >= 'A' && c <= 'Z': result[idx] = c - 'A' + 'a'
        default:                   result[idx] = c
        }
    }
    
	return string(result)
}