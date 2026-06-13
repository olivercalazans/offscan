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

package sniffer

/*
#cgo LDFLAGS: -lpcap
#include <pcap.h>
#include <stdlib.h>

int compile_bpf_filter(int linktype, const char* filter_str, struct bpf_program* fp) {
    pcap_t *p = pcap_open_dead(linktype, 65535);
    if (p == NULL) {
        return -1;
    }
    int res = pcap_compile(p, fp, filter_str, 1, 0xffffffff);
    pcap_close(p);
    return res;
}
*/
import "C"

import (
	"fmt"
	"offscan/internal/sysconf"
	"offscan/internal/utils"
	"unsafe"

	"golang.org/x/sys/unix"
)


func (s *Sniffer) compileFilter() ([]unix.SockFilter, error) {
    cFilterText := C.CString(s.filter)
    defer C.free(unsafe.Pointer(cFilterText))

    var bpfProg C.struct_bpf_program

	linkType, err := sysconf.GetIfaceLinkType(&s.iface)

	if err != nil {
		utils.Abort(fmt.Sprintf("%v", err))
	}

    if res := C.compile_bpf_filter(C.int(linkType), cFilterText, &bpfProg); res < 0 {
        return nil, fmt.Errorf("Invalid BPF filter syntax")
    }
    defer C.pcap_freecode(&bpfProg)

    numInstructions := int(bpfProg.bf_len)
    cInstructions   := unsafe.Slice((*unix.SockFilter)(unsafe.Pointer(bpfProg.bf_insns)), numInstructions)
    goInstructions  := make([]unix.SockFilter, numInstructions)
    
	copy(goInstructions, cInstructions)
    return goInstructions, nil
}