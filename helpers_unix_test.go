//go:build linux || darwin || solaris || aix || freebsd

package service

import (
	"strings"
	"testing"
)

// recordCommands replaces runCommand for the rest of the test. Each call's
// argv is appended to the returned slice, and its output is looked up in
// outputs by the space-joined argv.
func recordCommands(t *testing.T, outputs map[string]string) *[][]string { //nolint:unused // Used by darwin and systemd tests.
	t.Helper()
	var calls [][]string
	prev := runCommand
	runCommand = func(command string, readStdout bool, arguments ...string) (int, string, error) {
		argv := append([]string{command}, arguments...)
		calls = append(calls, argv)
		return 0, outputs[strings.Join(argv, " ")], nil
	}
	t.Cleanup(func() { runCommand = prev })
	return &calls
}

// stubPrivileged makes isPrivileged return v for the rest of the test.
func stubPrivileged(t *testing.T, v bool) { //nolint:unused // Used by darwin and systemd tests.
	t.Helper()
	prev := isPrivileged
	isPrivileged = func() bool { return v }
	t.Cleanup(func() { isPrivileged = prev })
}
