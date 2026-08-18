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
 * along with this program.  If not, see <https://gnu.org>.
 */

package sniffer

import (
	"fmt"
	"net"
	"offscan/internal/utils"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)


type Sniffer struct {
	iface         net.Interface
	filter        string
	promisc       bool
	resultCh      chan []byte
	wg            sync.WaitGroup
	fd            int
	epollFd       int
	stopEventFd   int
	stats         unix.TpacketStats
	promiscMreq  *unix.PacketMreq
	closed        bool
	closeMu       sync.Mutex
}



func NewSniffer(iface net.Interface, filter string, promisc bool) *Sniffer {
	return &Sniffer{
		iface:       iface,
		filter:      filter,
		promisc:     promisc,
		resultCh:    make(chan []byte, 100),
		fd:          -1,
		epollFd:     -1,
		stopEventFd: -1,
	}
}



func (s *Sniffer) Start() <-chan []byte {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	if s.closed || s.fd != -1 { return nil }

	if err := s.initRawSocket(); err != nil {
		utils.Abort(fmt.Sprintf("%v", err))
	}

	if err := s.configureSocket(); err != nil {
		unix.Close(s.fd)
		s.fd = -1
		utils.Abort(fmt.Sprintf("%v", err))
	}

	if err := s.setupEpoll(); err != nil {
		unix.Close(s.fd)
		s.fd = -1
		utils.Abort(fmt.Sprintf("%v", err))
	}

	s.wg.Add(1)
	go s.captureLoop()
	return s.resultCh
}



func (s *Sniffer) captureLoop() {
	defer s.wg.Done()
	defer close(s.resultCh)

	events := make([]unix.EpollEvent, 10)
	buf    := make([]byte, 65536)

	for {
		nEvents, err := unix.EpollWait(s.epollFd, events, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}

		for i := range nEvents{
			ev := &events[i]
			fd := int(ev.Fd)

			switch {
			case fd == s.stopEventFd:
				var val uint64
				_, _ = unix.Read(s.stopEventFd, (*[8]byte)(unsafe.Pointer(&val))[:])
				s.collectStats()
				return

			case fd == s.fd && (ev.Events&unix.EPOLLIN) != 0:
				n, _, err := unix.Recvfrom(s.fd, buf, 0)
				if err != nil {
					if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
						continue
					}
					return
				}

				pkt := make([]byte, n)
				copy(pkt, buf[:n])

				select {
				case s.resultCh <- pkt:
				default:
				}
			}
		}
	}
}



func (s *Sniffer) collectStats() {
	if s.fd == -1 {
		return
	}
	
	stats, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err == nil {
		s.stats = *stats
	}
}



func (s *Sniffer) Stop() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	if s.closed || s.stopEventFd == -1 { return }

	s.unblockEpollWait()
	s.wg.Wait()
	s.disablePromiscuous()
	s.closeDescriptors()	
	s.displayStats()
}



func (s *Sniffer) unblockEpollWait() {
	val := uint64(1)
	_, _ = unix.Write(s.stopEventFd, (*[8]byte)(unsafe.Pointer(&val))[:])
}



func (s *Sniffer) closeDescriptors() {
	if s.epollFd != -1 {
		unix.Close(s.epollFd)
		s.epollFd = -1
	}

	if s.stopEventFd != -1 {
		unix.Close(s.stopEventFd)
		s.stopEventFd = -1
	}
	
	if s.fd != -1 {
		unix.Close(s.fd)
		s.fd = -1
	}

	s.closed = true
}



func (s *Sniffer) displayStats() {
	fmt.Printf("[$] Packets received = %d\n", s.stats.Packets)
	
	if s.stats.Drops > 0 {
		fmt.Printf("[!] Packets dropped = %d\n", s.stats.Drops)
	}
}