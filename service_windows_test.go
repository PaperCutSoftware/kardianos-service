// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestTimeout(t *testing.T) {
	stopSpan := getStopTimeout()
	t.Log("Max Stop Duration", stopSpan)
}

func newWindowsService(t *testing.T, c *Config) *windowsService {
	t.Helper()
	s, err := windowsSystem{}.New(nil, c)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*windowsService)
}

func TestWindowsUserLevelUnsupported(t *testing.T) {
	_, err := windowsSystem{}.New(nil, &Config{Name: "test", ServiceLevel: ServiceLevelUser})
	if !errors.Is(err, ErrUnsupportedServiceLevel) {
		t.Errorf("err = %v, want %v", err, ErrUnsupportedServiceLevel)
	}
}

func TestWindowsAllUsersRejectsAccount(t *testing.T) {
	tests := []struct {
		name string
		c    Config
	}{
		{"UserName", Config{UserName: `DOMAIN\svc`}},
		{"Password", Config{Option: KeyValue{"Password": "secret"}}},
		{"Interactive", Config{Option: KeyValue{"Interactive": true}}},
	}
	for _, tt := range tests {
		c := tt.c
		c.Name = "test"
		c.ServiceLevel = ServiceLevelAllUsers
		if _, err := (windowsSystem{}).New(nil, &c); err == nil {
			t.Errorf("%s: New succeeded, want error", tt.name)
		}
	}
}

func TestWindowsMgrConfig(t *testing.T) {
	t.Run("System", func(t *testing.T) {
		ws := newWindowsService(t, &Config{
			Name:     "test",
			UserName: `DOMAIN\svc`,
			Option:   KeyValue{StartType: ServiceStartManual},
		})
		got := ws.mgrConfig()
		if got.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS {
			t.Errorf("ServiceType = %#x, want %#x", got.ServiceType, windows.SERVICE_WIN32_OWN_PROCESS)
		}
		if got.StartType != mgr.StartManual {
			t.Errorf("StartType = %d, want %d", got.StartType, mgr.StartManual)
		}
		if got.ServiceStartName != `DOMAIN\svc` {
			t.Errorf("ServiceStartName = %q, want %q", got.ServiceStartName, `DOMAIN\svc`)
		}
	})
	t.Run("AllUsers", func(t *testing.T) {
		ws := newWindowsService(t, &Config{
			Name:         "test",
			ServiceLevel: ServiceLevelAllUsers,
		})
		got := ws.mgrConfig()
		if got.ServiceType != 0x50 {
			t.Errorf("ServiceType = %#x, want 0x50", got.ServiceType)
		}
		if got.ServiceStartName != "" {
			t.Errorf("ServiceStartName = %q, want empty", got.ServiceStartName)
		}
	})
}

func TestAllUsersInstallRequiresPrivilege(t *testing.T) {
	stubPrivileged(t, false)
	ws := newWindowsService(t, &Config{Name: "test", ServiceLevel: ServiceLevelAllUsers})
	if err := ws.Install(); !errors.Is(err, ErrRequiresPrivilege) {
		t.Errorf("err = %v, want %v", err, ErrRequiresPrivilege)
	}
}

func TestAllUsersUninstallRequiresPrivilege(t *testing.T) {
	stubPrivileged(t, false)
	ws := newWindowsService(t, &Config{Name: "test", ServiceLevel: ServiceLevelAllUsers})
	if err := ws.Uninstall(); !errors.Is(err, ErrRequiresPrivilege) {
		t.Errorf("err = %v, want %v", err, ErrRequiresPrivilege)
	}
}

func TestWindowsAllUsersRejectsEnvVars(t *testing.T) {
	_, err := windowsSystem{}.New(nil, &Config{
		Name:         "test",
		ServiceLevel: ServiceLevelAllUsers,
		EnvVars:      map[string]string{"KEY": "value"},
	})
	if err == nil {
		t.Error("New succeeded, want error")
	}
}

func TestWindowsAllUsersCommandsRequirePrivilege(t *testing.T) {
	stubPrivileged(t, false)
	ws := newWindowsService(t, &Config{Name: "test", ServiceLevel: ServiceLevelAllUsers})

	tests := []struct {
		name string
		cmd  func() error
		want error
	}{
		{"Stop", ws.Stop, ErrRequiresPrivilege},
		{"Restart", ws.Restart, ErrRequiresPrivilege},
		{"Start", ws.Start, ErrUnsupportedOperation},
	}
	for _, tt := range tests {
		if err := tt.cmd(); !errors.Is(err, tt.want) {
			t.Errorf("%s err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestWindowsIsInstanceOf(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Svc_3c4a5", true},
		{"svc_3C4A5", true},
		{"Svc_3c4a5f0", true},
		{"Svc", false},
		{"Svc_", false},
		{"SvcX_3c4a5", false},
		{"Svc_Other", false},
	}
	for _, tt := range tests {
		if got := isInstanceOf(tt.name, "Svc"); got != tt.want {
			t.Errorf("isInstanceOf(%q, Svc) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWindowsOwnRunningInstance(t *testing.T) {
	stubProcessSession(t, map[uint32]uint32{20: 2, 30: 3})
	mine := instanceState{"Svc_aa", svc.Running, 20}
	other := instanceState{"Svc_bb", svc.Running, 30}
	denied := instanceState{"Svc_cc", svc.Running, 40}
	stopped := instanceState{"Svc_dd", svc.Stopped, 0}

	tests := []struct {
		name      string
		instances []instanceState
		want      string
	}{
		{"no instances", nil, ""},
		{"mine", []instanceState{mine}, "Svc_aa"},
		{"other session", []instanceState{other}, ""},
		{"access denied", []instanceState{denied}, ""},
		{"stopped", []instanceState{stopped}, ""},
		{"mix", []instanceState{other, denied, stopped, mine}, "Svc_aa"},
	}
	for _, tt := range tests {
		got, ok := ownRunningInstance(tt.instances, 2)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("%s: ownRunningInstance = %q, %v, want %q", tt.name, got, ok, tt.want)
		}
	}
}

func TestAllUsersAllCommandsRequirePrivilege(t *testing.T) {
	stubPrivileged(t, false)
	ws := newWindowsService(t, &Config{Name: "test", ServiceLevel: ServiceLevelAllUsers})
	for name, cmd := range map[string]func() error{"StartAll": ws.StartAll, "StopAll": ws.StopAll} {
		if err := cmd(); !errors.Is(err, ErrRequiresPrivilege) {
			t.Errorf("%s err = %v, want %v", name, err, ErrRequiresPrivilege)
		}
	}
}

func TestAllUsersAllCommandsOtherLevels(t *testing.T) {
	stubPrivileged(t, true)
	ws := newWindowsService(t, &Config{Name: "test"})
	for name, cmd := range map[string]func() error{"StartAll": ws.StartAll, "StopAll": ws.StopAll} {
		if err := cmd(); !errors.Is(err, ErrUnsupportedOperation) {
			t.Errorf("%s err = %v, want %v", name, err, ErrUnsupportedOperation)
		}
	}
}
