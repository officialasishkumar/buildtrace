//go:build !linux

package capture

import (
	"context"
	"errors"
	"os"
)

var errLinuxOnly = errors.New("packet capture needs Linux; on a Mac run buildtrace inside a Linux container or VM")

// Available reports whether packets can be captured in this process.
func Available() error { return errLinuxOnly }

// Sniff is not available on this platform.
func Sniff(context.Context, *Tracker) error { return errLinuxOnly }

// Hostname is a best-effort local hostname for the report.
func Hostname() string {
	h, _ := os.Hostname()
	return h
}
