package conv

import "strconv"



func StrToU8(s string) uint8 {
    n, err := strconv.ParseUint(s, 10, 8)

    if err != nil {
        return 0
    }

    return uint8(n)
}