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

package ifmode

import "encoding/binary"



func genlHdr(cmd, version uint8) []byte {
	return []byte{cmd, version, 0, 0} // genlmsghdr
}



func align4(n int) int { return (n + 3) &^ 3 }



func putAttr(buf []byte, typ uint16, data []byte) []byte {
	length := 4 + len(data)
	attr   := make([]byte, align4(length))
	
	binary.LittleEndian.PutUint16(attr[0:2], uint16(length))
	binary.LittleEndian.PutUint16(attr[2:4], typ)
	
	copy(attr[4:], data)
	
	return append(buf, attr...)
}



func putU32Attr(buf []byte, typ uint16, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	
	return putAttr(buf, typ, b)
}



func putStringAttr(buf []byte, typ uint16, s string) []byte {
	return putAttr(buf, typ, append([]byte(s), 0))
}