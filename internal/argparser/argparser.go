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

package argparser

import (
	"net"
	"offscan/internal/models"
	"offscan/internal/utils"
	"strconv"
)


type Argument struct {
    Required  bool
    Short     string
    Long      string
}



type ArgParser struct {
    args           []string
    duplicated     []string
    missingFlags   []string
    missingValues  []string
    errors         []string
}



func NewArgParser(args []string) *ArgParser {
    ap := &ArgParser{}
    
    ap.args          = args
    ap.duplicated    = make([]string, 0)
    ap.missingFlags  = make([]string, 0)
    ap.missingValues = make([]string, 0)

    return ap
}



func (ap *ArgParser) AbortIfHasError() {
    lenErr := len(ap.duplicated) + len(ap.missingFlags)
    lenErr += len(ap.errors) + len(ap.missingValues)
    lenErr += len(ap.args)

    if lenErr == 0 {
        return
    }

    ap.displayMissingFlags()
    ap.displayMissingValues()
    ap.displayDuplicated()
    ap.displayErrors()
    ap.displayRemainingArgs()
    
    utils.Abort("Error while parsing arguments")
}



func (ap *ArgParser) Bool(arg *Argument) bool {
    _, ok := ap.verifyIfHasFlags(arg)
    ap.removeFromTheList(arg)
    return ok
}



func (ap *ArgParser) Float64(arg *Argument) (float64, bool) {
    hasLong, ok := ap.verifyIfHasFlags(arg)

    if !ok {
        return 0, false
    }

    str, hasValue := ap.getValue(arg, hasLong)

    if !hasValue {
        return 0, false
    }

	float, err := strconv.ParseFloat(str, 64)

    if err != nil {
        ap.AddError(arg, err)
        return 0, false
    }

    return float, true
}



func (ap *ArgParser) Iface(arg *Argument) (net.Interface, bool) {
    hasLong, ok := ap.verifyIfHasFlags(arg)

    if !ok {
        return net.Interface{}, false 
    }

    str, hasValue := ap.getValue(arg, hasLong)

    if !hasValue {
        return net.Interface{}, false
    }

    iface, err := net.InterfaceByName(str)

    if err != nil {
        ap.AddError(arg, err)
        return net.Interface{}, false
    }

    return *iface, true
}



func (ap *ArgParser) Int(arg *Argument) (int, bool) {
    hasLong, ok := ap.verifyIfHasFlags(arg)

    if !ok { return 0, false }

    str, hasValue := ap.getValue(arg, hasLong)

    if !hasValue {
        return 0, false
    }

    i, err := strconv.Atoi(str)

    if err != nil {
        ap.AddError(arg, err)
        return 0, false
    }

    return i, true
}



func (ap *ArgParser) IP(arg *Argument) (models.IPv4, bool) {
    hasLong, ok := ap.verifyIfHasFlags(arg)

    if !ok {
        return models.IPv4{}, false
    }

    str, hasValue := ap.getValue(arg, hasLong)

    if !hasValue {
        return models.IPv4{}, false
    }

    ip, err := models.StrToIPv4(str)

    if err != nil {
        ap.AddError(arg, err)
        return models.IPv4{}, false
    }

    return ip, true
}



func (ap *ArgParser) MAC(arg *Argument) (models.MAC, bool) {
    hasLong, ok := ap.verifyIfHasFlags(arg)

    if !ok {
        return models.MAC{}, false
    }

    str, hasValue := ap.getValue(arg, hasLong)
    
    if !hasValue {
        return models.MAC{}, false
    }

    mac, err := models.ParseMAC(str)

    if err != nil {
        ap.AddError(arg, err)
        return models.MAC{}, false
    }

    return mac, true
}



func (ap *ArgParser) String(arg *Argument) (string, bool) {
    hasLong, ok := ap.verifyIfHasFlags(arg)

    if !ok { return "", false }

    return ap.getValue(arg, hasLong)
}