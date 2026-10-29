//go:build darwin || linux

package service

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTrusted(t *testing.T) {
	const (
		root  = 0
		user  = 501
		wheel = 0
		admin = 80
		staff = 20
	)
	tests := []struct {
		name     string
		uid, gid uint32
		mode     os.FileMode
		want     bool
	}{
		{"root:admin 0775", root, admin, 0775, runtime.GOOS == "darwin"},
		{"root:wheel 0755", root, wheel, 0755, true},
		{"root:staff 0775", root, staff, 0775, false},
		{"root 0777", root, wheel, 0777, false},
		{"user 0755", user, wheel, 0755, false},
	}
	for _, tt := range tests {
		if got := trusted(tt.uid, tt.gid, tt.mode); got != tt.want {
			t.Errorf("%s: trusted = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// stubOwnerStat replaces ownerStat for the rest of the test.
func stubOwnerStat(t *testing.T, f func(path string) (uint32, uint32, os.FileMode, error)) {
	t.Helper()
	prev := ownerStat
	ownerStat = f
	t.Cleanup(func() { ownerStat = prev })
}

func TestOwnershipWalk(t *testing.T) {
	// The walk resolves symlinks on the real filesystem, so start from a real
	// path and fake only the ownership.
	file := filepath.Join(t.TempDir(), "a", "b", "exe")
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0755); err != nil {
		t.Fatal(err)
	}
	file, err := filepath.EvalSymlinks(file)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for p := file; ; p = filepath.Dir(p) {
		want = append(want, p)
		if p == "/" {
			break
		}
	}

	t.Run("checks every parent", func(t *testing.T) {
		var seen []string
		stubOwnerStat(t, func(path string) (uint32, uint32, os.FileMode, error) {
			seen = append(seen, path)
			return 0, 0, 0755, nil
		})
		if err := checkExecutableOwnership(file); err != nil {
			t.Fatal(err)
		}
		if strings.Join(seen, "\n") != strings.Join(want, "\n") {
			t.Errorf("checked %q, want %q", seen, want)
		}
	})

	t.Run("names first bad directory", func(t *testing.T) {
		a, b := filepath.Dir(filepath.Dir(file)), filepath.Dir(file)
		stubOwnerStat(t, func(path string) (uint32, uint32, os.FileMode, error) {
			if path == a || path == b {
				return 0, 0, 0777, nil
			}
			return 0, 0, 0755, nil
		})
		err := checkExecutableOwnership(file)
		if err == nil || !strings.HasPrefix(err.Error(), b+":") {
			t.Errorf("err = %v, want it to name %s", err, b)
		}
	})

	t.Run("passes back stat error", func(t *testing.T) {
		statErr := errors.New("stat failed")
		stubOwnerStat(t, func(path string) (uint32, uint32, os.FileMode, error) {
			return 0, 0, 0, statErr
		})
		if err := checkExecutableOwnership(file); !errors.Is(err, statErr) {
			t.Errorf("err = %v, want %v", err, statErr)
		}
	})
}

func TestOwnershipRealFS(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("temp files are owned by root when running as root")
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, nil, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := checkExecutableOwnership(target); err == nil {
		t.Error("user-owned file passed")
	}
	err := checkExecutableOwnership(link)
	if err == nil || !strings.Contains(err.Error(), "target:") {
		t.Errorf("err = %v, want it to name the resolved target", err)
	}
}
