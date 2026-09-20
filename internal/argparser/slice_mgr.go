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
	"fmt"
	"slices"
	"strings"
)



func (ap *ArgParser) getFlagIndex(flag string) int {
	return slices.Index(ap.args, flag)
}



func (ap *ArgParser) getValueIndex(indexFlag int) (int, bool) {
    indexValue := indexFlag + 1

    if indexValue >= len(ap.args) {
        return 0, false
    }

    value := ap.args[indexValue]

    if strings.HasPrefix(value, "-") {
        return 0, false
    }

    return indexValue, true
}



func (ap *ArgParser) addMissingValueWarn(arg string) {
	ap.missingValues = append(ap.missingValues, arg)
}



func (ap *ArgParser) addMissReqFlagsWarn(arg *Argument) {
	line            := formatArg(arg)
	ap.missingFlags  = append(ap.missingFlags, line)
}



func (ap *ArgParser) addDuplicatedWarn(arg *Argument) {
	line 		  := formatArg(arg)
	ap.duplicated  = append(ap.duplicated, line)
}



func (ap *ArgParser) AddError(arg *Argument, err error) {
	flags     := formatArg(arg)
	line      := fmt.Sprintf("%s: %s", flags, err.Error())
	ap.errors  = append(ap.errors, line)
}



func (ap *ArgParser) removeFromTheList(arg *Argument) {
	for range ap.count(arg.Long) {
		index := ap.getFlagIndex(arg.Long)
		ap.remove(index)
	}

	for range ap.count(arg.Short) {
		index := ap.getFlagIndex(arg.Short)
		ap.remove(index)
	}
}



func (ap *ArgParser) remove(index int) {
	if i, hasValue := ap.getValueIndex(index); hasValue {
		ap.removeFlagAndValue(index, i)
	} else {
		ap.removeIndex(index)
	}
}



func (ap *ArgParser) removeIndex(indexFlag int) {
    ap.args = slices.Delete(ap.args, indexFlag, indexFlag + 1)
}



func (ap *ArgParser) removeFlagAndValue(indexFlag, indexValue int) {
    ap.args = slices.Delete(ap.args, indexFlag, indexValue + 1)
}



func (ap *ArgParser) count(flag string) int {
	var count int

	for _, v := range ap.args {
		if v == flag { count++ }
	}

	return count
}