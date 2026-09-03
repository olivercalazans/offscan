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

package models

import "fmt"


type Uptime struct {
    Days  uint16
    Hours uint8
}



func (u *Uptime) isLessThanHour() bool {
    return u.Hours == 255
}



func (u *Uptime) isUknown() bool {
	return u.Days == 0 && u.Hours == 0
}



func (u *Uptime) String() string {
	if u.isUknown() {
		return "unknown"
	}

    if u.isLessThanHour() {
        return "less than 1h"
    }
 
	if u.Days > 0 {
        return fmt.Sprintf("%dd %02dh", u.Days, u.Hours)
    }
    
	return fmt.Sprintf("%dh", u.Hours)
}