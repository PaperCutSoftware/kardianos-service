// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
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
