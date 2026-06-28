//go:build linux

package girth

import (
	"math"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// platformFallocate allocates real blocks for the file (Linux fallocate(2)).
func platformFallocate(f *os.File, size int64) error {
	return unix.Fallocate(int(f.Fd()), 0, 0, size)
}

// platformSyncFileRangeWrite kicks asynchronous writeback for the byte range
// (Linux sync_file_range(2)).
func platformSyncFileRangeWrite(f *os.File, offset, nbytes int64) {
	_ = unix.SyncFileRange(int(f.Fd()), offset, nbytes, unix.SYNC_FILE_RANGE_WRITE)
}

// platformSetMaxPacingRate sets the kernel egress pacing ceiling for the socket
// (Linux SO_MAX_PACING_RATE; pairs with the fq qdisc).
func platformSetMaxPacingRate(conn *net.UDPConn, bps uint64) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	bytesPerSec := bps / 8
	if bytesPerSec > math.MaxUint32 {
		bytesPerSec = math.MaxUint32
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MAX_PACING_RATE, int(bytesPerSec))
	})
}
