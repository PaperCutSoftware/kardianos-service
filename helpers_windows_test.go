package service

import "testing"

func stubPrivileged(t *testing.T, v bool) {
	t.Helper()
	prev := isPrivileged
	isPrivileged = func() bool { return v }
	t.Cleanup(func() { isPrivileged = prev })
}
