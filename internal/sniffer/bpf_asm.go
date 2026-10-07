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

// bpf_asm.go provides small constructors for classic BPF (cBPF)
// instructions. Each constructor returns a unix.SockFilter ready to be
// assembled into a program and attached to a socket via SO_ATTACH_FILTER.

package sniffer

import "golang.org/x/sys/unix"

// Instruction classes (bits 0..2 of the code field).
const (
	bpfLD   = 0x00 // load into A
	bpfLDX  = 0x01 // load into X
	bpfST   = 0x02 // store A into scratch memory
	bpfALU  = 0x04 // arithmetic/logic on A
	bpfJMP  = 0x05 // conditional jump
	bpfRET  = 0x06 // return from filter
	bpfMISC = 0x07 // miscellaneous (TAX, TXA, ...)
)

// Size modifiers (bits 3..4).
const (
	bpfW = 0x00 // word   (4 bytes)
	bpfH = 0x08 // half   (2 bytes)
	bpfB = 0x10 // byte   (1 byte)
)

// Addressing modes (bits 5..7).
const (
	bpfIMM = 0x00 // immediate
	bpfABS = 0x20 // absolute packet offset
	bpfIND = 0x40 // indexed by X
	bpfMSH = 0xa0 // 4 * (P[k] & 0x0f)  — used for IPv4 IHL
)

// ALU operations (bits 4..7 when class == bpfALU).
const (
	bpfADD = 0x00
	bpfSUB = 0x10
	bpfMUL = 0x20
	bpfDIV = 0x30
	bpfOR  = 0x40
	bpfAND = 0x50
	bpfLSH = 0x60
	bpfRSH = 0x70
	bpfNEG = 0x80
	bpfMOD = 0x90
	bpfXOR = 0xa0
)

// Jump operations (bits 4..7 when class == bpfJMP).
const (
	bpfJA   = 0x00
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJGE  = 0x30
	bpfJSET = 0x40
)

// MISC operations (bits 4..7 when class == bpfMISC).
const (
	bpfTAX = 0x00 // X = A
	bpfTXA = 0x80 // A = X
)

// Source modifier: use X instead of K for ALU/JMP operations (bit 3).
const bpfX = 0x08

// BPFAcceptAll is the snap length returned by filters on match: 256 KiB,
// enough for any packet AF_PACKET can deliver.
const BPFAcceptAll uint32 = 0x00040000



// ---------------------------------------------------------------------------
// Loads
// ---------------------------------------------------------------------------

// LDH loads a 16-bit big-endian value from an absolute packet offset.
func LDH(off uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfLD | bpfH | bpfABS, K: off}
}

// LDW loads a 32-bit big-endian value from an absolute packet offset.
func LDW(off uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: off}
}

// LDB loads an 8-bit value from an absolute packet offset.
func LDB(off uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfLD | bpfB | bpfABS, K: off}
}

// LDBInd loads P[X + k] into A (indexed byte load).
func LDBInd(k uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfLD | bpfB | bpfIND, K: k}
}

// LDXMSH sets X = (P[k] & 0x0f) * 4, i.e. the IPv4 IHL in bytes.
// Useful for filters that need to skip IPv4 options before reading L4 fields.
//
// func LDXMSH(off uint32) unix.SockFilter {
// 	return unix.SockFilter{Code: bpfLDX | bpfB | bpfMSH, K: off}
// }

// LDHInd loads P[X + k] into A (indexed 16-bit big-endian load).
//
// func LDHInd(k uint32) unix.SockFilter {
// 	return unix.SockFilter{Code: bpfLD | bpfH | bpfIND, K: k}
// }

// LDWInd loads P[X + k] into A (indexed 32-bit big-endian load).
//
// func LDWInd(k uint32) unix.SockFilter {
// 	return unix.SockFilter{Code: bpfLD | bpfW | bpfIND, K: k}
// }



// ---------------------------------------------------------------------------
// Jumps
// ---------------------------------------------------------------------------

// JEQ jumps to Jt if A == K, otherwise to Jf.
func JEQ(k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: bpfJMP | bpfJEQ, Jt: jt, Jf: jf, K: k}
}

// JSET jumps to Jt if (A & K) != 0, otherwise to Jf.
func JSET(k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: bpfJMP | bpfJSET, Jt: jt, Jf: jf, K: k}
}

// JGT jumps to Jt if A > K, otherwise to Jf.
//
// func JGT(k uint32, jt, jf uint8) unix.SockFilter {
// 	return unix.SockFilter{Code: bpfJMP | bpfJGT, Jt: jt, Jf: jf, K: k}
// }

// JGE jumps to Jt if A >= K, otherwise to Jf.
//
// func JGE(k uint32, jt, jf uint8) unix.SockFilter {
// 	return unix.SockFilter{Code: bpfJMP | bpfJGE, Jt: jt, Jf: jf, K: k}
// }



// ---------------------------------------------------------------------------
// ALU
// ---------------------------------------------------------------------------

// AND performs A = A & K.
func AND(k uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfALU | bpfAND, K: k}
}

// LSH performs A = A << K.
func LSH(k uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfALU | bpfLSH, K: k}
}

// ORX performs A = A | X.
func ORX() unix.SockFilter {
	return unix.SockFilter{Code: bpfALU | bpfOR | bpfX}
}



// ---------------------------------------------------------------------------
// MISC
// ---------------------------------------------------------------------------

// TAX performs X = A.
func TAX() unix.SockFilter {
	return unix.SockFilter{Code: bpfMISC | bpfTAX}
}

// ST stores A into scratch memory slot M[k]. tcpdump emits it as an artifact
// of some composed expressions; it is a no-op unless a subsequent load reads
// from the same slot.
func ST(k uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfST, K: k}
}



// ---------------------------------------------------------------------------
// Return
// ---------------------------------------------------------------------------

// RET returns K as the number of bytes to capture (0 = drop).
func RET(k uint32) unix.SockFilter {
	return unix.SockFilter{Code: bpfRET, K: k}
}