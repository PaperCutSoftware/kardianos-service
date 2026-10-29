package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// newDarwinService builds a launchd service at the given level, with the
// user's home directory stubbed to /home/test.
func newDarwinService(t *testing.T, level ServiceLevel, opts KeyValue) *darwinLaunchdService {
	t.Helper()
	prev := userHomeDir
	userHomeDir = func() (string, error) { return "/home/test", nil }
	t.Cleanup(func() { userHomeDir = prev })

	s, err := darwinSystem{}.New(nil, &Config{Name: "svc", ServiceLevel: level, Option: opts})
	if err != nil {
		t.Fatal(err)
	}
	return s.(*darwinLaunchdService)
}

func TestDarwinServiceFilePath(t *testing.T) {
	tests := []struct {
		level ServiceLevel
		want  string
	}{
		{ServiceLevelUser, "/home/test/Library/LaunchAgents/svc.plist"},
		{ServiceLevelAllUsers, "/Library/LaunchAgents/svc.plist"},
		{ServiceLevelSystem, "/Library/LaunchDaemons/svc.plist"},
	}
	for _, tt := range tests {
		got, err := newDarwinService(t, tt.level, nil).getServiceFilePath()
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("%s: path = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestDarwinLogDir(t *testing.T) {
	tests := []struct {
		level ServiceLevel
		opts  KeyValue
		want  string
	}{
		{ServiceLevelUser, nil, "/home/test"},
		{ServiceLevelAllUsers, nil, defaultDarwinLogDirectory},
		{ServiceLevelSystem, nil, defaultDarwinLogDirectory},
		{ServiceLevelUser, KeyValue{optionLogDirectory: "/custom"}, "/custom"},
		{ServiceLevelAllUsers, KeyValue{optionLogDirectory: "/custom"}, "/custom"},
		{ServiceLevelSystem, KeyValue{optionLogDirectory: "/custom"}, "/custom"},
	}
	for _, tt := range tests {
		got, err := newDarwinService(t, tt.level, tt.opts).logDir()
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("%s %v: logDir = %q, want %q", tt.level, tt.opts, got, tt.want)
		}
	}
}

// stubLibraryDir points darwinLibraryDir and userHomeDir at a temp directory
// holding empty LaunchAgents and LaunchDaemons directories, and returns it.
func stubLibraryDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"LaunchAgents", "LaunchDaemons", "Library/LaunchAgents"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	prevLib, prevHome := darwinLibraryDir, userHomeDir
	darwinLibraryDir = dir
	userHomeDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { darwinLibraryDir, userHomeDir = prevLib, prevHome })
	return dir
}

func TestAllUsersInstallRequiresPrivilege(t *testing.T) {
	stubPrivileged(t, false)
	calls := recordCommands(t, nil)
	s := newDarwinService(t, ServiceLevelAllUsers, nil)
	dir := stubLibraryDir(t)

	if err := s.Install(); !errors.Is(err, ErrRequiresPrivilege) {
		t.Errorf("Install err = %v, want %v", err, ErrRequiresPrivilege)
	}
	if len(*calls) != 0 {
		t.Errorf("ran %q, want no commands", *calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "LaunchAgents", "svc.plist")); !os.IsNotExist(err) {
		t.Errorf("plist was created: %v", err)
	}
}

func TestAllUsersUninstallRequiresPrivilege(t *testing.T) {
	stubPrivileged(t, false)
	calls := recordCommands(t, nil)
	s := newDarwinService(t, ServiceLevelAllUsers, nil)
	dir := stubLibraryDir(t)
	plist := filepath.Join(dir, "LaunchAgents", "svc.plist")
	if err := os.WriteFile(plist, nil, 0644); err != nil {
		t.Fatal(err)
	}

	if err := s.Uninstall(); !errors.Is(err, ErrRequiresPrivilege) {
		t.Errorf("Uninstall err = %v, want %v", err, ErrRequiresPrivilege)
	}
	if len(*calls) != 0 {
		t.Errorf("ran %q, want no commands", *calls)
	}
	if _, err := os.Stat(plist); err != nil {
		t.Errorf("plist was removed: %v", err)
	}
}

func TestAllUsersCommandsRefuseWhenPrivileged(t *testing.T) {
	stubPrivileged(t, true)
	calls := recordCommands(t, nil)
	s := newDarwinService(t, ServiceLevelAllUsers, nil)

	commands := map[string]func() error{
		"Start":   s.Start,
		"Stop":    s.Stop,
		"Restart": s.Restart,
		"Status":  func() error { _, err := s.Status(); return err },
	}
	for name, cmd := range commands {
		if err := cmd(); !errors.Is(err, ErrUserContextRequired) {
			t.Errorf("%s err = %v, want %v", name, err, ErrUserContextRequired)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("ran %q, want no commands", *calls)
	}
}

func TestDarwinAllUsersUninstallSkipsStop(t *testing.T) {
	stubPrivileged(t, true)
	tests := []struct {
		level    ServiceLevel
		plist    string
		wantStop bool
	}{
		{ServiceLevelAllUsers, "LaunchAgents/svc.plist", false},
		{ServiceLevelSystem, "LaunchDaemons/svc.plist", true},
		{ServiceLevelUser, "Library/LaunchAgents/svc.plist", true},
	}
	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			calls := recordCommands(t, nil)
			s := newDarwinService(t, tt.level, nil)
			plist := filepath.Join(stubLibraryDir(t), tt.plist)
			if err := os.WriteFile(plist, nil, 0644); err != nil {
				t.Fatal(err)
			}

			if err := s.Uninstall(); err != nil {
				t.Fatal(err)
			}
			stopped := false
			for _, c := range *calls {
				if len(c) == 3 && c[0] == "launchctl" && c[1] == "unload" && c[2] == plist {
					stopped = true
				}
			}
			if stopped != tt.wantStop {
				t.Errorf("launchctl unload ran = %v, want %v (calls %q)", stopped, tt.wantStop, *calls)
			}
			if _, err := os.Stat(plist); !os.IsNotExist(err) {
				t.Errorf("plist not removed: %v", err)
			}
		})
	}
}

func TestDarwinStopCommand(t *testing.T) {
	stubPrivileged(t, false)
	tests := []struct {
		level ServiceLevel
		want  string
	}{
		// AllUsers stops by label, because Uninstall may have removed the plist.
		{ServiceLevelAllUsers, "launchctl remove svc"},
		{ServiceLevelSystem, "launchctl unload /Library/LaunchDaemons/svc.plist"},
	}
	for _, tt := range tests {
		calls := recordCommands(t, nil)
		if err := newDarwinService(t, tt.level, nil).Stop(); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 1 || strings.Join((*calls)[0], " ") != tt.want {
			t.Errorf("%s: ran %q, want %q", tt.level, *calls, tt.want)
		}
	}
}

func TestAllUsersAllCommandsRequirePrivilege(t *testing.T) {
	stubPrivileged(t, false)
	calls := recordCommands(t, nil)
	s := newDarwinService(t, ServiceLevelAllUsers, nil)

	for name, cmd := range map[string]func() error{"StartAll": s.StartAll, "StopAll": s.StopAll} {
		if err := cmd(); !errors.Is(err, ErrRequiresPrivilege) {
			t.Errorf("%s err = %v, want %v", name, err, ErrRequiresPrivilege)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("ran %q, want no commands", *calls)
	}
}

func TestAllUsersAllCommandsOtherLevels(t *testing.T) {
	stubPrivileged(t, true)
	calls := recordCommands(t, nil)
	for _, level := range []ServiceLevel{ServiceLevelSystem, ServiceLevelUser} {
		s := newDarwinService(t, level, nil)
		for name, cmd := range map[string]func() error{"StartAll": s.StartAll, "StopAll": s.StopAll} {
			if err := cmd(); !errors.Is(err, ErrUnsupportedOperation) {
				t.Errorf("%s %s err = %v, want %v", level, name, err, ErrUnsupportedOperation)
			}
		}
	}
	if len(*calls) != 0 {
		t.Errorf("ran %q, want no commands", *calls)
	}
}

func TestDarwinParseGUIUsers(t *testing.T) {
	const loginwindow = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
	tests := []struct {
		name string
		out  string
		want []uint32
	}{
		{"empty", "", nil},
		{"no loginwindow", "  501 /usr/sbin/cfprefsd\n    0 /sbin/launchd\n", nil},
		{"root only", "    0 " + loginwindow + "\n", nil},
		{
			"two users",
			"    1 /sbin/launchd\n" +
				"  501 " + loginwindow + "\n" +
				"    0 " + loginwindow + "\n" +
				"  501 /Applications/Safari.app/Contents/MacOS/Safari\n" +
				"  502 " + loginwindow + "\n" +
				"  501 " + loginwindow + "\n" +
				"  503 /Applications/Not loginwindow.app/Contents/MacOS/helper\n",
			[]uint32{501, 502},
		},
	}
	for _, tt := range tests {
		got := parseGUIUsers(tt.out)
		if fmt.Sprint(got) != fmt.Sprint(tt.want) {
			t.Errorf("%s: parseGUIUsers = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// guiUsersPS is "ps -axo uid=,comm=" output with users 501 and 502 logged in.
const guiUsersPS = "  501 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow\n" +
	"  502 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow\n"

const psGUIUsers = "ps -axo uid=,comm="

func TestDarwinStopAllCommands(t *testing.T) {
	stubPrivileged(t, true)
	// User 502 has no copy loaded, which is not an error.
	calls := stubCommands(t, func(argv []string) (int, string, error) {
		switch strings.Join(argv, " ") {
		case psGUIUsers:
			return 0, guiUsersPS, nil
		case "launchctl bootout gui/502/svc":
			return launchctlNoSuchProcess, "", errors.New("Boot-out failed: 3: No such process")
		}
		return 0, "", nil
	})

	if err := newDarwinService(t, ServiceLevelAllUsers, nil).StopAll(); err != nil {
		t.Fatal(err)
	}
	want := []string{"launchctl bootout gui/501/svc", "launchctl bootout gui/502/svc", psGUIUsers}
	if got := joinCalls(*calls); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ran %q, want %q", got, want)
	}
}

func TestDarwinStartAllCommands(t *testing.T) {
	stubPrivileged(t, true)
	// User 501's copy is loaded, so kickstart starts it. User 502's isn't, so
	// it is bootstrapped.
	calls := stubCommands(t, func(argv []string) (int, string, error) {
		switch strings.Join(argv, " ") {
		case psGUIUsers:
			return 0, guiUsersPS, nil
		case "launchctl kickstart gui/502/svc":
			return launchctlNotFound, "", errors.New(`Could not find service "svc"`)
		}
		return 0, "", nil
	})

	if err := newDarwinService(t, ServiceLevelAllUsers, nil).StartAll(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl bootstrap gui/502 /Library/LaunchAgents/svc.plist",
		"launchctl kickstart gui/501/svc",
		"launchctl kickstart gui/502/svc",
		psGUIUsers,
	}
	if got := joinCalls(*calls); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ran %q, want %q", got, want)
	}
}

func TestDarwinAllCommandsReturnErrors(t *testing.T) {
	stubPrivileged(t, true)
	stubCommands(t, func(argv []string) (int, string, error) {
		if strings.Join(argv, " ") == psGUIUsers {
			return 0, guiUsersPS, nil
		}
		return 1, "", errors.New("failed: " + argv[len(argv)-1])
	})
	s := newDarwinService(t, ServiceLevelAllUsers, nil)

	for name, cmd := range map[string]func() error{"StartAll": s.StartAll, "StopAll": s.StopAll} {
		err := cmd()
		if err == nil || !strings.Contains(err.Error(), "501") || !strings.Contains(err.Error(), "502") {
			t.Errorf("%s err = %v, want both users' failures", name, err)
		}
	}
}

func TestDarwinAllCommandsRunConcurrently(t *testing.T) {
	stubPrivileged(t, true)
	var (
		mu      sync.Mutex
		started int
	)
	all := make(chan struct{})
	stubCommands(t, func(argv []string) (int, string, error) {
		if strings.Join(argv, " ") == psGUIUsers {
			return 0, guiUsersPS, nil
		}
		mu.Lock()
		ch := all
		started++
		if started == 2 {
			close(ch)
		}
		mu.Unlock()
		select {
		case <-ch:
			return 0, "", nil
		case <-time.After(5 * time.Second):
			return 1, "", errors.New("users' commands ran one at a time")
		}
	})
	s := newDarwinService(t, ServiceLevelAllUsers, nil)

	for name, cmd := range map[string]func() error{"StartAll": s.StartAll, "StopAll": s.StopAll} {
		mu.Lock()
		started = 0
		all = make(chan struct{})
		mu.Unlock()
		if err := cmd(); err != nil {
			t.Errorf("%s err = %v", name, err)
		}
	}
}

// joinCalls returns each recorded call's argv joined with spaces, sorted,
// because each user's commands run concurrently.
func joinCalls(calls [][]string) []string {
	var out []string
	for _, c := range calls {
		out = append(out, strings.Join(c, " "))
	}
	sort.Strings(out)
	return out
}
