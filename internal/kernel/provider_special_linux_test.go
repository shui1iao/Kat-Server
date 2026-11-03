package kernel

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestProviderSpecialFileRejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.fifo")
	if e := syscall.Mkfifo(path, 0600); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, e := readLimited(path); result <- e }()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("special source accepted")
		}
	case <-time.After(100 * time.Millisecond):
		// Unblock only this synthetic FIFO so a failing old implementation does
		// not leak a goroutine or hang the remainder of the regression suite.
		w, e := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if e != nil {
			t.Fatal(e)
		}
		w.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("old read did not settle")
		}
		t.Fatal("provider file/cache open blocked on a non-regular source")
	}
}
