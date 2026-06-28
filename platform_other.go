//go:build !linux

package girth

import (
	"errors"
	"net"
	"os"
)

// errNoFallocate signals the caller to fall back to Truncate; off Linux there is
// no portable preallocation primitive (Windows SetFileValidData needs an
// elevated privilege), so we let the OS create a sparse file via Truncate.
var errNoFallocate = errors.New("girth: fallocate unsupported on this platform")

func platformFallocate(_ *os.File, _ int64) error { return errNoFallocate }

// platformSyncFileRangeWrite is a no-op off Linux: there is no portable async
// writeback-hint syscall. Durability still happens at Close/Sync.
func platformSyncFileRangeWrite(_ *os.File, _, _ int64) {}

// platformSetMaxPacingRate is a no-op off Linux: there is no SO_MAX_PACING_RATE
// equivalent. The userspace pacer in the sender still applies.
func platformSetMaxPacingRate(_ *net.UDPConn, _ uint64) {}
