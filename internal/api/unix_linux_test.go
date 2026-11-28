//go:build linux

package api

import (
	"net"
	"os"
	"testing"
)

func TestPeerListenerSO_PEERCREDValidation(t *testing.T) {
	pl := &peerListener{uid: uint32(os.Geteuid())}

	// Non-UnixConn (e.g. TCP/Pipe) must always be rejected fail-closed.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if pl.allowed(c1) {
		t.Fatal("peerListener.allowed accepted non-UnixConn")
	}

	// Real Unix domain connection from same process uid must pass SO_PEERCRED check,
	// whereas a mismatched non-root uid simulated on a non-root peerListener must fail.
	dir := t.TempDir()
	sock := dir + "/peer.sock"
	ln, err := listenPrivateUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		sc, _ := ln.Accept()
		accepted <- sc
	}()
	cc, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	sc := <-accepted
	if sc == nil {
		t.Fatal("Accept returned nil")
	}
	defer sc.Close()

	if !pl.allowed(sc) {
		t.Fatal("peerListener.allowed rejected same-UID Unix socket peer")
	}
}
