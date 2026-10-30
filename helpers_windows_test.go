package service

import (
	"testing"

	"golang.org/x/sys/windows"
)

func stubPrivileged(t *testing.T, v bool) {
	t.Helper()
	prev := isPrivileged
	isPrivileged = func() bool { return v }
	t.Cleanup(func() { isPrivileged = prev })
}

func stubProcessSession(t *testing.T, sessions map[uint32]uint32) {
	t.Helper()
	prev := processSession
	processSession = func(pid uint32) (uint32, error) {
		if s, ok := sessions[pid]; ok {
			return s, nil
		}
		return 0, windows.ERROR_ACCESS_DENIED
	}
	t.Cleanup(func() { processSession = prev })
}
