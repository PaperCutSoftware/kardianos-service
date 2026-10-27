package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
