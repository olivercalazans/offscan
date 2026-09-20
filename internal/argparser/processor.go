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

import "slices"



func (ap *ArgParser) getValue(arg *Argument, hasLong bool) (string, bool)  {
    if hasLong {
        return  ap.getFlagValue(arg.Long)
    }
    
    return ap.getFlagValue(arg.Short)
}



func (ap *ArgParser) verifyIfHasFlags(arg *Argument) (bool, bool) {
	hasLong  := slices.Contains(ap.args, arg.Long)
	hasShort := slices.Contains(ap.args, arg.Short)

	if arg.Required && !hasLong && !hasShort {
		ap.addMissReqFlagsWarn(arg)
		return false, false
	}

    if hasLong && hasShort {
        ap.addDuplicatedWarn(arg)
        ap.removeFromTheList(arg)
        return false, false
    }

    var count int

    if hasLong  { count = ap.count(arg.Long)  }
    if hasShort { count = ap.count(arg.Short) }

    if count > 1 {
        ap.addDuplicatedWarn(arg)
        ap.removeFromTheList(arg)
        return false, false
    }

	return hasLong, (hasLong || hasShort)
}



func (ap *ArgParser) getFlagValue(flag string) (string, bool) {
    indexFlag      := slices.Index(ap.args, flag)
    indexValue, ok := ap.getValueIndex(indexFlag)

    if !ok {
        ap.addMissingValueWarn(flag)
        ap.removeIndex(indexFlag)
        return "", false
    }
    
    value := ap.args[indexValue]
    ap.removeFlagAndValue(indexFlag, indexValue)
    
    return value, true
}