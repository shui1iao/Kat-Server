//go:build !unix

package tlscert

import "os"

// On non-POSIX platforms the administrator must secure the directory ACL.
func trustedChallengeDir(fi os.FileInfo) bool { return fi != nil && fi.IsDir() }
