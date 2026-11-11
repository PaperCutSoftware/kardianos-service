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
		{"Start", ws.Start, ErrRequiresPrivilege},
	}
	for _, tt := range tests {
		if err := tt.cmd(); !errors.Is(err, tt.want) {
			t.Errorf("%s err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestWindowsInstancesOf(t *testing.T) {
	const instance = serviceUserServiceInstance | serviceUserOwnProcess
	tests := []struct {
		reason  string
		service serviceState
		want    bool
	}{
		{"instance", serviceState{"Svc_3c4a5", instance, windows.SERVICE_RUNNING, 20}, true},
		{"name case differs", serviceState{"svc_3C4A5", instance, windows.SERVICE_RUNNING, 20}, true},
		{"longer suffix", serviceState{"Svc_3c4a5f0", instance, windows.SERVICE_RUNNING, 20}, true},
		{"keeps state", serviceState{"Svc_bb", instance, windows.SERVICE_STOP_PENDING, 50}, true},
		{"no instance bit", serviceState{"Svc_db", windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_RUNNING, 10}, false},
		{"template", serviceState{"Svc", serviceUserOwnProcess, windows.SERVICE_STOPPED, 0}, false},
		{"empty suffix", serviceState{"Svc_", instance, windows.SERVICE_RUNNING, 20}, false},
		{"other template", serviceState{"SvcX_aa", instance, windows.SERVICE_RUNNING, 30}, false},
		{"non-hex suffix", serviceState{"Svc_Other", instance, windows.SERVICE_RUNNING, 20}, false},
		{"other template's instance", serviceState{"Svc_helper_aa", instance, windows.SERVICE_RUNNING, 40}, false},
	}
	for _, tt := range tests {
		got := instancesOf([]serviceState{tt.service}, "Svc")
		if (len(got) == 1) != tt.want {
			t.Errorf("%s: instancesOf(%q) = %v, want included %v", tt.reason, tt.service.name, got, tt.want)
			continue
		}
		if tt.want && got[0] != tt.service {
			t.Errorf("%s: instancesOf(%q) = %v, want %v", tt.reason, tt.service.name, got[0], tt.service)
		}
	}
}

func TestWindowsOwnInstance(t *testing.T) {
	// The caller is in session 2. Processes 20-23 are in session 2, 30 in
	// session 3, and 40 can't be read.
	stubProcessSession(t, map[uint32]uint32{20: 2, 21: 2, 22: 2, 23: 2, 30: 3})
	const instance = serviceUserServiceInstance | serviceUserOwnProcess
	template := serviceState{"Svc", serviceUserOwnProcess, windows.SERVICE_STOPPED, 0}
	running := serviceState{"Svc_4f2a1c", instance, windows.SERVICE_RUNNING, 20}
	stopping := serviceState{"Svc_4f2a1c", instance, windows.SERVICE_STOP_PENDING, 21}
	paused := serviceState{"Svc_4f2a1c", instance, windows.SERVICE_PAUSED, 22}
	stopped := serviceState{"Svc_4f2a1c", instance, windows.SERVICE_STOPPED, 0}
	other := serviceState{"Svc_9e01b7", instance, windows.SERVICE_RUNNING, 30}
	denied := serviceState{"Svc_77aa01", instance, windows.SERVICE_RUNNING, 40}
	donor := serviceState{"cbdhsvc_4f2a1c", instance, windows.SERVICE_RUNNING, 23}
	otherDonor := serviceState{"cbdhsvc_9e01b7", instance, windows.SERVICE_RUNNING, 30}

	tests := []struct {
		name     string
		services []serviceState
		want     serviceState
		found    bool
		err      error
	}{
		{"not installed", []serviceState{running}, serviceState{}, false, ErrNotInstalled},
		{"no instances", []serviceState{template}, serviceState{}, false, nil},
		{"running", []serviceState{template, other, denied, running}, running, true, nil},
		{"stopping", []serviceState{template, stopping}, stopping, true, nil},
		{"paused", []serviceState{template, paused}, paused, true, nil},
		{"other session only", []serviceState{template, other, otherDonor}, serviceState{}, false, nil},
		{"access denied", []serviceState{template, denied}, serviceState{}, false, nil},
		{"stopped, found by suffix", []serviceState{template, other, stopped, donor}, stopped, true, nil},
		{"suffix without instance", []serviceState{template, other, donor}, serviceState{}, false, nil},
		{"stopped, no suffix", []serviceState{template, stopped}, serviceState{}, false, nil},
	}
	for _, tt := range tests {
		got, found, err := ownInstance(tt.services, "Svc", 2)
		if got != tt.want || found != tt.found || !errors.Is(err, tt.err) {
			t.Errorf("%s: ownInstance = %v, %v, %v, want %v, %v, %v", tt.name, got, found, err, tt.want, tt.found, tt.err)
		}
	}

	if _, _, err := ownInstance([]serviceState{template, running}, "Svc", 0); !errors.Is(err, errNonInteractiveSession) {
		t.Errorf("session 0: err = %v, want %v", err, errNonInteractiveSession)
	}
	if _, _, err := ownInstance([]serviceState{running}, "Svc", 0); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("session 0, not installed: err = %v, want %v", err, ErrNotInstalled)
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

func TestWindowsLogonSuffix(t *testing.T) {
	// The caller is in session 2. Process 20 is in session 2, 30 in session 3.
	stubProcessSession(t, map[uint32]uint32{20: 2, 30: 3})
	const instance = serviceUserServiceInstance | serviceUserOwnProcess
	mine := serviceState{"cbdhsvc_4f2a1c", instance, windows.SERVICE_RUNNING, 20}
	other := serviceState{"cbdhsvc_9e01b7", instance, windows.SERVICE_RUNNING, 30}
	stopped := serviceState{"Svc_4f2a1c", instance, windows.SERVICE_STOPPED, 0}
	notInstance := serviceState{"Spooler_4f2a1c", windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_RUNNING, 20}
	noSuffix := serviceState{"cbdhsvc", instance, windows.SERVICE_RUNNING, 20}

	tests := []struct {
		name     string
		services []serviceState
		want     string
	}{
		{"none", nil, ""},
		{"mine", []serviceState{mine}, "4f2a1c"},
		{"other session", []serviceState{other}, ""},
		{"stopped", []serviceState{stopped}, ""},
		{"not an instance", []serviceState{notInstance}, ""},
		{"no suffix", []serviceState{noSuffix}, ""},
		{"mix", []serviceState{other, stopped, notInstance, noSuffix, mine}, "4f2a1c"},
	}
	for _, tt := range tests {
		got, ok := logonSuffix(tt.services, 2)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("%s: logonSuffix = %q, %v, want %q", tt.name, got, ok, tt.want)
		}
	}
}
