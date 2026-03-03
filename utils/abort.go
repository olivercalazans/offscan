package utils

import (
	"fmt"
	"os"
)



func Abort(msg string) {
    fmt.Fprintf(os.Stderr, "[ ERROR ] %s\n", msg)
    os.Exit(1)
}