//go:build unix

package tlscert

import (
	"os"
	"syscall"
)

func trustedChallengeDir(fi os.FileInfo) bool {
	if fi == nil || !fi.IsDir() || fi.Mode().Perm()&0022 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == uint32(os.Geteuid()))
}
