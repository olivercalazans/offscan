package utils

import (
	"fmt"
	"strconv"
)



func ParseChannel(channel string) (int, error) {
	num, err := strconv.Atoi(channel)
	if err != nil {
		return 0, fmt.Errorf("'%s' is an invalid number", channel)
	}

	if num < 1 || num > 165 {
		return 0, fmt.Errorf("The channel must be between 1 and 165 (input: %d)", num)
	}

	return num, nil
}