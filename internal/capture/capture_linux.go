//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const packetOutgoing = 4 // PACKET_OUTGOING in linux/if_packet.h

// Available reports whether packets can be captured in this process.
func Available() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return errors.New("no permission to capture packets: run as root, inside a container, or in a user namespace (unshare -rn)")
		}
		return err
	}
	syscall.Close(fd)
	return nil
}

// Sniff reads every IP packet in the current network namespace into t until
// ctx is cancelled. Loopback traffic is only mined for DNS answers.
func Sniff(ctx context.Context, t *Tracker) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("packet socket: %w", err)
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval(int64(200 * time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	loopback := map[int]bool{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if i.Flags&net.FlagLoopback != 0 {
				loopback[i.Index] = true
			}
		}
	}
	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("recvfrom: %w", err)
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || n <= 0 {
			continue
		}
		p, ok := ParseIP(buf[:n], ll.Pkttype == packetOutgoing)
		if !ok {
			continue
		}
		t.Handle(p, !loopback[ll.Ifindex])
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Hostname is a best-effort local hostname for the report.
func Hostname() string {
	h, _ := os.Hostname()
	return h
}
