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

package packet

import "net"



func calculateChecksum(sum uint32, data []byte) uint16 {
    i := 0

	for i+1 < len(data) {
        sum += (uint32(data[i]) << 8) | uint32(data[i+1])
        i += 2
    }

	if i < len(data) {
        sum += uint32(data[i]) << 8
    }

	for (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }

	return ^uint16(sum)
}



func TcpUdpSum(header []byte, srcIP, dstIP net.IP, protocol uint8) uint16 {
    var sum uint32 = 0

    src := srcIP.To4()
    dst := dstIP.To4()
    if src == nil || dst == nil {
        return 0
    }

    sum += (uint32(src[0]) << 8) | uint32(src[1])
    sum += (uint32(src[2]) << 8) | uint32(src[3])

	sum += (uint32(dst[0]) << 8) | uint32(dst[1])
    sum += (uint32(dst[2]) << 8) | uint32(dst[3])

    sum += uint32(protocol)
    sum += uint32(len(header))

    return calculateChecksum(sum, header)
}



func IcmpSum(header []byte) uint16 {
    return calculateChecksum(0, header)
}



func Ipv4Sum(header []byte) uint16 {
    return calculateChecksum(0, header)
}