package ifconfig

import (
	"fmt"
	"syscall"
	"unsafe"
)



const (
	SIOCSIWFREQ = 0x8B04 // Set frequency/channel
)



type iwreq struct {
	ifrName [16]byte
	ifrData [16]byte
}



type iw_freq struct {
	m     int32
	e     int16
	i     uint8
	flags uint8
}



func TrySetChannel(ifaceName string, channel int) error {
	validateChannel(channel)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var wrq iwreq
	copy(wrq.ifrName[:], ifaceName)

	freq := iw_freq{
		m: int32(channel),
		e: 0,
		i: 0,
	}

	*(*iw_freq)(unsafe.Pointer(&wrq.ifrData[0])) = freq

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCSIWFREQ), uintptr(unsafe.Pointer(&wrq)))

	if errno != 0 {
		return fmt.Errorf("ioctl error: %v", errno)
	}

	return nil
}
