package sockets

import (
	"fmt"
	"net"
	"offscan/utils"

	"golang.org/x/sys/unix"
)



type Layer2Socket struct {
    fd   int
    addr unix.SockaddrLinklayer
}



func NewL2Socket(iface *net.Interface) *Layer2Socket {
    fd := createL2Socket()
    
    bindL2SocketToDevice(fd, iface)
    setSocketBuffer(fd)

    addr := unix.SockaddrLinklayer{
        Protocol : htons(unix.ETH_P_ALL),
        Ifindex  : iface.Index,
        Halen    : 6,
    }

    return &Layer2Socket{fd: fd, addr: addr}
}



func createL2Socket() int {
    fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))

	if err != nil {
        utils.Abort(fmt.Sprintf("Failed to create RAW layer 2 socket: %v", err))
    }

    return fd
}



func bindL2SocketToDevice(fd int, iface *net.Interface) {
    if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("Failed to bind socket to interface: %v", err))
    }
}



func setSocketBuffer(fd int) {
    if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1024*1024); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("Failed to set socket buffer: %v", err))
    }
}



func htons(i uint16) uint16 {
    return (i<<8)&0xff00 | i>>8
}



func (s *Layer2Socket) Send(frame []byte) {
    err := unix.Sendto(s.fd, frame, 0, &s.addr)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to send frame: %v", err))
    }
}



func (s *Layer2Socket) Close() error {
    if s.fd >= 0 {
        err := unix.Close(s.fd)
        s.fd = -1
        return err
    }

    return nil
}