// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	version = "windows-service"

	StartType             = "StartType"
	ServiceStartManual    = "manual"
	ServiceStartDisabled  = "disabled"
	ServiceStartAutomatic = "automatic"

	OnFailure              = "OnFailure"
	OnFailureRestart       = "restart"
	OnFailureReboot        = "reboot"
	OnFailureNoAction      = "noaction"
	OnFailureDelayDuration = "OnFailureDelayDuration"
	OnFailureResetPeriod   = "OnFailureResetPeriod"

	errnoServiceDoesNotExist syscall.Errno = 1060
)

// golang.org/x/sys/windows does not export the per-user service types.
const (
	serviceUserService    = 0x40 // SERVICE_USER_SERVICE
	serviceUserOwnProcess = windows.SERVICE_WIN32_OWN_PROCESS | serviceUserService
)

// mockable for tests
var isPrivileged = func() bool { return windows.GetCurrentProcessToken().IsElevated() }

type windowsService struct {
	i Interface
	*Config
	level ServiceLevel

	errSync      sync.Mutex
	stopStartErr error
}

// WindowsLogger allows using windows specific logging methods.
type WindowsLogger struct {
	ev   *eventlog.Log
	errs chan<- error
}

type windowsSystem struct{}

func (windowsSystem) String() string {
	return version
}
func (windowsSystem) Detect() bool {
	return true
}
func (windowsSystem) Interactive() bool {
	return interactive
}
func (windowsSystem) New(i Interface, c *Config) (Service, error) {
	level, err := c.serviceLevel()
	if err != nil {
		return nil, err
	}
	switch level {
	case ServiceLevelUser:
		return nil, ErrUnsupportedServiceLevel
	case ServiceLevelAllUsers:
		// Per-user instances always run as the logged-in user.
		if c.UserName != "" || c.Option.string("Password", "") != "" || c.Option.bool("Interactive", false) {
			return nil, errors.New("AllUsers services run as the logged-in user and cannot set UserName, Password or Interactive")
		}
		if len(c.EnvVars) > 0 {
			return nil, errors.New("AllUsers services cannot set EnvVars: per-user instances don't receive the template's environment")
		}
	}
	ws := &windowsService{
		i:      i,
		Config: c,
		level:  level,
	}
	return ws, nil
}

func init() {
	ChooseSystem(windowsSystem{})
}

func (l WindowsLogger) send(err error) error {
	if err == nil {
		return nil
	}
	if l.errs != nil {
		l.errs <- err
	}
	return err
}

// Error logs an error message.
func (l WindowsLogger) Error(v ...interface{}) error {
	return l.send(l.ev.Error(3, fmt.Sprint(v...)))
}

// Warning logs an warning message.
func (l WindowsLogger) Warning(v ...interface{}) error {
	return l.send(l.ev.Warning(2, fmt.Sprint(v...)))
}

// Info logs an info message.
func (l WindowsLogger) Info(v ...interface{}) error {
	return l.send(l.ev.Info(1, fmt.Sprint(v...)))
}

// Errorf logs an error message.
func (l WindowsLogger) Errorf(format string, a ...interface{}) error {
	return l.send(l.ev.Error(3, fmt.Sprintf(format, a...)))
}

// Warningf logs an warning message.
func (l WindowsLogger) Warningf(format string, a ...interface{}) error {
	return l.send(l.ev.Warning(2, fmt.Sprintf(format, a...)))
}

// Infof logs an info message.
func (l WindowsLogger) Infof(format string, a ...interface{}) error {
	return l.send(l.ev.Info(1, fmt.Sprintf(format, a...)))
}

// NError logs an error message and an event ID.
func (l WindowsLogger) NError(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Error(eventID, fmt.Sprint(v...)))
}

// NWarning logs an warning message and an event ID.
func (l WindowsLogger) NWarning(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Warning(eventID, fmt.Sprint(v...)))
}

// NInfo logs an info message and an event ID.
func (l WindowsLogger) NInfo(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Info(eventID, fmt.Sprint(v...)))
}

// NErrorf logs an error message and an event ID.
func (l WindowsLogger) NErrorf(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Error(eventID, fmt.Sprintf(format, a...)))
}

// NWarningf logs an warning message and an event ID.
func (l WindowsLogger) NWarningf(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Warning(eventID, fmt.Sprintf(format, a...)))
}

// NInfof logs an info message and an event ID.
func (l WindowsLogger) NInfof(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Info(eventID, fmt.Sprintf(format, a...)))
}

var interactive = false

func init() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		panic(err)
	}
	interactive = !isService
}

func (ws *windowsService) String() string {
	if len(ws.DisplayName) > 0 {
		return ws.DisplayName
	}
	return ws.Name
}

func (ws *windowsService) Platform() string {
	return version
}

func (ws *windowsService) setError(err error) {
	ws.errSync.Lock()
	defer ws.errSync.Unlock()
	ws.stopStartErr = err
}
func (ws *windowsService) getError() error {
	ws.errSync.Lock()
	defer ws.errSync.Unlock()
	return ws.stopStartErr
}

func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	if err := ws.i.Start(ws); err != nil {
		ws.setError(err)
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop:
			changes <- svc.Status{State: svc.StopPending}
			if err := ws.i.Stop(ws); err != nil {
				ws.setError(err)
				return true, 2
			}
			break loop
		case svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			var err error
			if wsShutdown, ok := ws.i.(Shutdowner); ok {
				err = wsShutdown.Shutdown(ws)
			} else {
				err = ws.i.Stop(ws)
			}
			if err != nil {
				ws.setError(err)
				return true, 2
			}
			break loop
		default:
			continue loop
		}
	}

	return false, 0
}

func lowPrivMgr() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

func lowPrivSvc(m *mgr.Mgr, name string) (*mgr.Service, error) {
	return openService(m, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_START|windows.SERVICE_STOP)
}

// openService opens name with only the given access rights.
func openService(m *mgr.Mgr, name string, access uint32) (*mgr.Service, error) {
	h, err := windows.OpenService(m.Handle, syscall.StringToUTF16Ptr(name), access)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Handle: h, Name: name}, nil
}

func (ws *windowsService) setEnvironmentVariablesInRegistry() error {
	if len(ws.EnvVars) == 0 {
		return nil
	}

	k, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+ws.Name,
		registry.QUERY_VALUE|registry.SET_VALUE|registry.CREATE_SUB_KEY)
	if err != nil {
		return fmt.Errorf("failed creating env var registry key, err = %v", err)
	}
	envStrings := make([]string, 0, len(ws.EnvVars))
	for k, v := range ws.EnvVars {
		envStrings = append(envStrings, k+"="+v)
	}

	if err := k.SetStringsValue("Environment", envStrings); err != nil {
		return fmt.Errorf("failed setting env var registry key, err = %v", err)
	}
	if err := k.Close(); err != nil {
		return fmt.Errorf("failed closing env var registry key, err = %v", err)
	}
	return nil
}

// mgrConfig returns the service manager configuration used to create the service.
func (ws *windowsService) mgrConfig() mgr.Config {
	var startType int32
	switch ws.Option.string(StartType, ServiceStartAutomatic) {
	case ServiceStartAutomatic:
		startType = mgr.StartAutomatic
	case ServiceStartManual:
		startType = mgr.StartManual
	case ServiceStartDisabled:
		startType = mgr.StartDisabled
	}

	var serviceType uint32
	switch ws.level {
	case ServiceLevelAllUsers:
		serviceType = serviceUserOwnProcess
	default:
		serviceType = windows.SERVICE_WIN32_OWN_PROCESS
		if ws.Option.bool("Interactive", false) {
			serviceType = serviceType | windows.SERVICE_INTERACTIVE_PROCESS
		}
	}

	return mgr.Config{
		DisplayName:      ws.DisplayName,
		Description:      ws.Description,
		StartType:        uint32(startType),
		ServiceStartName: ws.UserName,
		Password:         ws.Option.string("Password", ""),
		Dependencies:     ws.Dependencies,
		DelayedAutoStart: ws.Option.bool("DelayedAutoStart", false),
		ServiceType:      serviceType,
	}
}

func (ws *windowsService) Install() error {
	if ws.level == ServiceLevelAllUsers && !isPrivileged() {
		return ErrRequiresPrivilege
	}
	exepath, err := ws.execPath()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if err := ws.setEnvironmentVariablesInRegistry(); err != nil {
		return err
	}

	s, err := m.OpenService(ws.Name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ws.Name)
	}

	s, err = m.CreateService(ws.Name, exepath, ws.mgrConfig(), ws.Arguments...)
	if err != nil {
		return err
	}
	if onFailure := ws.Option.string(OnFailure, ""); onFailure != "" {
		var delay = 1 * time.Second
		if d, err := time.ParseDuration(ws.Option.string(OnFailureDelayDuration, "1s")); err == nil {
			delay = d
		}
		var actionType int
		switch onFailure {
		case OnFailureReboot:
			actionType = mgr.ComputerReboot
		case OnFailureRestart:
			actionType = mgr.ServiceRestart
		case OnFailureNoAction:
			actionType = mgr.NoAction
		default:
			actionType = mgr.ServiceRestart
		}
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{
			{
				Type:  actionType,
				Delay: delay,
			},
		}, uint32(ws.Option.int(OnFailureResetPeriod, 10))); err != nil {
			return err
		}
	}
	defer s.Close()
	err = eventlog.InstallAsEventCreate(ws.Name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		if !strings.Contains(err.Error(), "exists") {
			s.Delete()
			return fmt.Errorf("SetupEventLogSource() failed: %s", err)
		}
	}
	return nil
}

func (ws *windowsService) Uninstall() error {
	if ws.level == ServiceLevelAllUsers && !isPrivileged() {
		return ErrRequiresPrivilege
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ws.Name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", ws.Name)
	}
	defer s.Close()
	err = s.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(ws.Name)
	if err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}
	return nil
}

func (ws *windowsService) Run() error {
	ws.setError(nil)
	if !interactive {
		// Return error messages from start and stop routines
		// that get executed in the Execute method.
		// Guarded with a mutex as it may run a different thread
		// (callback from windows).
		runErr := svc.Run(ws.Name, ws)
		startStopErr := ws.getError()
		if startStopErr != nil {
			return startStopErr
		}
		if runErr != nil {
			return runErr
		}
		return nil
	}
	err := ws.i.Start(ws)
	if err != nil {
		return err
	}

	sigChan := make(chan os.Signal)

	signal.Notify(sigChan, os.Interrupt)

	<-sigChan

	return ws.i.Stop(ws)
}

func (ws *windowsService) Status() (Status, error) {
	if ws.level == ServiceLevelAllUsers {
		return ws.allUsersStatus()
	}
	m, err := lowPrivMgr()
	if err != nil {
		return StatusUnknown, err
	}
	defer m.Disconnect()

	s, err := lowPrivSvc(m, ws.Name)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == errnoServiceDoesNotExist {
			return StatusUnknown, ErrNotInstalled
		}
		return StatusUnknown, err
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return StatusUnknown, err
	}

	switch status.State {
	case svc.StartPending:
		fallthrough
	case svc.Running:
		return StatusRunning, nil
	case svc.PausePending:
		fallthrough
	case svc.Paused:
		fallthrough
	case svc.ContinuePending:
		fallthrough
	case svc.StopPending:
		fallthrough
	case svc.Stopped:
		return StatusStopped, nil
	default:
		return StatusUnknown, fmt.Errorf("unknown status %v", status)
	}
}

func (ws *windowsService) Start() error {
	if ws.level == ServiceLevelAllUsers {
		return ws.allUsersStart()
	}
	m, err := lowPrivMgr()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := lowPrivSvc(m, ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func (ws *windowsService) Stop() error {
	if ws.level == ServiceLevelAllUsers {
		return ws.allUsersStop()
	}
	m, err := lowPrivMgr()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := lowPrivSvc(m, ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()

	return ws.stopWait(s)
}

func (ws *windowsService) Restart() error {
	if ws.level == ServiceLevelAllUsers {
		return ws.allUsersRestart()
	}
	m, err := lowPrivMgr()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := lowPrivSvc(m, ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()

	err = ws.stopWait(s)
	if err != nil {
		return err
	}

	return s.Start()
}

func (ws *windowsService) stopWait(s *mgr.Service) error {
	// First stop the service. Then wait for the service to
	// actually stop before starting it.
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}

	timeDuration := time.Millisecond * 50

	timeout := time.After(getStopTimeout() + (timeDuration * 2))
	tick := time.NewTicker(timeDuration)
	defer tick.Stop()

	for status.State != svc.Stopped {
		select {
		case <-tick.C:
			status, err = s.Query()
			if err != nil {
				return err
			}
		case <-timeout:
			break
		}
	}
	return nil
}

// Windows creates a per-user service instance named "<Name>_<hex>", in
// each user's session at logon.
//
// Users aren't given the required permissions to Start, Stop and Restart their
// services, but they can query their status.

type instanceState struct {
	name  string
	state svc.State
	pid   uint32
}

// determines if the name is a per-user service instance of the template service
func isInstanceOf(name, template string) bool {
	prefix := template + "_"
	if len(name) <= len(prefix) || !strings.EqualFold(name[:len(prefix)], prefix) {
		return false
	}
	for _, c := range name[len(prefix):] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// listInstances lists all instances with their state and process ID
func listInstances(m *mgr.Mgr, template string) ([]instanceState, error) {
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	var instances []instanceState
	for _, name := range names {
		if !isInstanceOf(name, template) {
			continue
		}
		status, err := queryService(m, name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		instances = append(instances, instanceState{name, status.State, status.ProcessId})
	}
	return instances, nil
}

func queryService(m *mgr.Mgr, name string) (svc.Status, error) {
	s, err := openService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return svc.Status{}, err
	}
	defer s.Close()
	return s.Query()
}

// mockable for tests
var processSession = func(pid uint32) (uint32, error) {
	var session uint32
	err := windows.ProcessIdToSessionId(pid, &session)
	return session, err
}

func ownRunningInstance(instances []instanceState, session uint32) (string, bool) {
	for _, in := range instances {
		if in.pid == 0 {
			continue
		}

		// we can't read another user's session, so any successful reads are
		// guaranteed to be ours
		if s, err := processSession(in.pid); err == nil && s == session {
			return in.name, true
		}
	}
	return "", false
}

func (ws *windowsService) ownInstance(m *mgr.Mgr) (name string, running bool, err error) {
	t, err := openService(m, ws.Name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "", false, ErrNotInstalled
	}
	if err != nil {
		return "", false, err
	}
	t.Close()

	instances, err := listInstances(m, ws.Name)
	if err != nil {
		return "", false, err
	}
	session, err := processSession(windows.GetCurrentProcessId())
	if err != nil {
		return "", false, err
	}
	name, running = ownRunningInstance(instances, session)
	return name, running, nil
}

func (ws *windowsService) allUsersStatus() (Status, error) {
	m, err := lowPrivMgr()
	if err != nil {
		return StatusUnknown, err
	}
	defer m.Disconnect()

	_, running, err := ws.ownInstance(m)
	if err != nil {
		return StatusUnknown, err
	}
	if running {
		return StatusRunning, nil
	}
	return StatusStopped, nil
}

// allUsersStart is not supported yet: a stopped instance has no process, so
// it can't be matched to the caller's session.
func (ws *windowsService) allUsersStart() error {
	return ErrUnsupportedOperation
}

func (ws *windowsService) allUsersStop() error {
	if !isPrivileged() {
		return ErrRequiresPrivilege
	}
	m, err := lowPrivMgr()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	name, running, err := ws.ownInstance(m)
	if err != nil || !running {
		return err
	}
	return stopInstances(m, []string{name})
}

func (ws *windowsService) allUsersRestart() error {
	if !isPrivileged() {
		return ErrRequiresPrivilege
	}
	m, err := lowPrivMgr()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	name, running, err := ws.ownInstance(m)
	if err != nil {
		return err
	}
	if !running {
		return ws.allUsersStart()
	}
	if err := stopInstances(m, []string{name}); err != nil {
		return err
	}
	return startInstance(m, name)
}

// StartAll starts every user's stopped instance. Instances only exist for
// logged-on users, and only from their first logon after install.
func (ws *windowsService) StartAll() error {
	m, instances, err := ws.allInstances()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	var errs []error
	for _, in := range instances {
		if in.state == svc.Stopped {
			errs = append(errs, startInstance(m, in.name))
		}
	}
	return errors.Join(errs...)
}

// StopAll stops every user's running instance, and returns once they have
// stopped.
func (ws *windowsService) StopAll() error {
	m, instances, err := ws.allInstances()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	var names []string
	for _, in := range instances {
		if in.state != svc.Stopped {
			names = append(names, in.name)
		}
	}
	return stopInstances(m, names)
}

// Will list instances that are
func (ws *windowsService) allInstances() (*mgr.Mgr, []instanceState, error) {
	if ws.level != ServiceLevelAllUsers {
		return nil, nil, ErrUnsupportedOperation
	}
	if !isPrivileged() {
		return nil, nil, ErrRequiresPrivilege
	}
	m, err := lowPrivMgr()
	if err != nil {
		return nil, nil, err
	}
	instances, err := listInstances(m, ws.Name)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, instances, nil
}

// runs as the service's owner
func startInstance(m *mgr.Mgr, name string) error {
	s, err := openService(m, name, windows.SERVICE_START)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// stopInstances sends a stop to every named instance
func stopInstances(m *mgr.Mgr, names []string) error {
	var errs []error
	var stopping []*mgr.Service
	for _, name := range names {
		s, err := openService(m, name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		defer s.Close()
		_, err = s.Control(svc.Stop)
		switch {
		case errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		default:
			stopping = append(stopping, s)
		}
	}
	errs = append(errs, waitStopped(stopping, getStopTimeout()))
	return errors.Join(errs...)
}

// polls for all services to stop
func waitStopped(services []*mgr.Service, timeout time.Duration) error {
	const interval = 50 * time.Millisecond
	deadline := time.Now().Add(timeout + 2*interval)
	var errs []error
	for {
		var pending []*mgr.Service
		for _, s := range services {
			status, err := s.Query()
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
			case status.State != svc.Stopped:
				pending = append(pending, s)
			}
		}
		services = pending
		if len(services) == 0 {
			return errors.Join(errs...)
		}
		if time.Now().After(deadline) {
			for _, s := range services {
				errs = append(errs, fmt.Errorf("%s: did not stop within %v", s.Name, timeout))
			}
			return errors.Join(errs...)
		}
		time.Sleep(interval)
	}
}

// getStopTimeout fetches the time before windows will kill the service.
func getStopTimeout() time.Duration {
	// For default and paths see https://support.microsoft.com/en-us/kb/146092
	defaultTimeout := time.Millisecond * 20000
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, registry.READ)
	if err != nil {
		return defaultTimeout
	}
	sv, _, err := key.GetStringValue("WaitToKillServiceTimeout")
	if err != nil {
		return defaultTimeout
	}
	v, err := strconv.Atoi(sv)
	if err != nil {
		return defaultTimeout
	}
	return time.Millisecond * time.Duration(v)
}

func (ws *windowsService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return ws.SystemLogger(errs)
}
func (ws *windowsService) SystemLogger(errs chan<- error) (Logger, error) {
	el, err := eventlog.Open(ws.Name)
	if err != nil {
		return nil, err
	}
	return WindowsLogger{el, errs}, nil
}
