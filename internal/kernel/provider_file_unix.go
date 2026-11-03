//go:build !windows

package kernel

import (
	"os"
	"syscall"
)

// Nonblocking open prevents a regular-file-to-FIFO replacement between the
// path check and open from hanging the core. It has no effect on regular I/O.
func openProviderFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
