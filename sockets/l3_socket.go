package sockets

import (
	"fmt"
	"net"
	"offscan/iface"
	"offscan/utils"

	"golang.org/x/sys/unix"
)



type Layer3Socket struct {
    fd int
}



func NewL3Socket(iface *iface.Iface) *Layer3Socket {
    fd := createL3Socket()
    
    enableIPHdrIncl(fd)
    bindL3SocketToDevice(fd, iface)

    return &Layer3Socket{fd: fd}
}



func createL3Socket() int {
    fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)

	if err != nil {
        utils.Abort(fmt.Sprintf("Failed to create RAW layer 3 socket: %v", err))
    }

    return fd
}



func enableIPHdrIncl(fd int) {
    if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("Failed to bind socket to interface: %v", err))
    }
}



func bindL3SocketToDevice(fd int, iface *iface.Iface) {
    if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name()); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("Failed to bind socket to interface: %v", err))
    }
}



func (s *Layer3Socket) SendTo(packet []byte, dst net.IP) {
    dst4 := dst.To4()
    
    if dst4 == nil {
        utils.Abort(fmt.Sprintf("The destination address is not a IPv4: %v", dst))
    }

    addr := &unix.SockaddrInet4{
        Port: 0,
        Addr: [4]byte{dst4[0], dst4[1], dst4[2], dst4[3]},
    }

    err := unix.Sendto(s.fd, packet, 0, addr)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to send frame: %v", err))
    }
}



func (s *Layer3Socket) Close() error {
    if s.fd >= 0 {
        err := unix.Close(s.fd)
        s.fd = -1
        return err
    }
    return nil
}