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

package frame80211


func MinimalRariotapHeader(buffer []byte) {
	buffer[0]  = 0x00  // Header revision
	buffer[1]  = 0x00  // Header pad
	buffer[2]  = 0x0c  // Header length
	buffer[3]  = 0x00  //
	buffer[4]  = 0x04  // Bitmap
	buffer[5]  = 0x80  //
	buffer[6]  = 0x00  //
	buffer[7]  = 0x00  //
	buffer[8]  = 0x02  // Rate
	buffer[9]  = 0x00  // Rate pad
	buffer[10] = 0x18  // TX flags
	buffer[11] = 0x00  //
}
