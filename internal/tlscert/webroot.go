package tlscert

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Each directory is opened relative to the previously pinned directory. The
// before/after comparison rejects replacement during the walk. Deployment must
// also protect the webroot from other writers with the same service identity.
func challengeDir(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("webroot must be absolute")
	}
	path = filepath.Clean(path)
	anchor := filepath.VolumeName(path) + string(os.PathSeparator)
	r, e := os.OpenRoot(anchor)
	if e != nil {
		return nil, e
	}
	dirs := strings.FieldsFunc(strings.TrimPrefix(path, anchor), func(c rune) bool { return c == rune(os.PathSeparator) })
	// Require an existing, operator-selected webroot. Only the two RFC challenge
	// subdirectories are created; no symlink in the configured path is accepted.
	n := len(dirs)
	dirs = append(dirs, ".well-known", "acme-challenge")
	for i, name := range dirs {
		if i >= n {
			parent, err := r.Stat(".")
			if err != nil || !trustedChallengeDir(parent) {
				r.Close()
				return nil, errors.New("unsafe ACME challenge directory owner or permissions")
			}
		}
		before, err := r.Lstat(name)
		if errors.Is(err, os.ErrNotExist) && i >= n {
			if err = r.Mkdir(name, 0755); err != nil && !errors.Is(err, os.ErrExist) {
				r.Close()
				return nil, err
			}
			before, err = r.Lstat(name)
		}
		if err != nil {
			r.Close()
			return nil, err
		}
		if !before.IsDir() {
			r.Close()
			return nil, errors.New("ACME webroot component is not a directory or is a symlink")
		}
		next, err := r.OpenRoot(name)
		r.Close()
		if err != nil {
			return nil, err
		}
		pinned, err := next.Stat(".")
		if err != nil || !os.SameFile(before, pinned) || i >= n-1 && !trustedChallengeDir(pinned) {
			next.Close()
			return nil, errors.New("unsafe or changed ACME webroot directory")
		}
		r = next
	}
	return r, nil
}
func writeChallenge(webroot, name, body string) (func() error, error) {
	if len(name) == 0 || len(name) > 255 || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return nil, errors.New("invalid ACME challenge token")
	}
	dir, e := challengeDir(webroot)
	if e != nil {
		return nil, e
	}
	f, e := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		dir.Close()
		return nil, e
	}
	created, e := f.Stat()
	if e != nil {
		f.Close()
		dir.Close()
		return nil, e
	}
	cleanup := func() error {
		defer dir.Close()
		cur, err := dir.Lstat(name)
		parent, pe := dir.Stat(".")
		// On Unix keep the file open through comparison/removal so the inode cannot
		// be recycled. Directory checks exclude other untrusted namespace writers.
		if runtime.GOOS == "windows" {
			_ = f.Close()
		} else {
			defer f.Close()
		}
		if pe != nil || !trustedChallengeDir(parent) {
			return errors.New("ACME challenge directory no longer trusted")
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !cur.Mode().IsRegular() || !os.SameFile(cur, created) {
			return errors.New("ACME challenge file replaced; not removing")
		}
		return dir.Remove(name)
	}
	if _, e = f.WriteString(body); e == nil {
		e = f.Chmod(0644)
	}
	if e != nil {
		return nil, errors.Join(fmt.Errorf("write ACME challenge: %w", e), cleanup())
	}
	return cleanup, nil
}
