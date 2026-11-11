//go:build linux || darwin || solaris || aix || freebsd

package service

import "testing"

func TestUserServiceLevel(t *testing.T) {
	tests := []struct {
		name        string
		level       ServiceLevel
		userService bool
		want        ServiceLevel
		wantErr     bool
	}{
		{name: "default", want: ServiceLevelSystem},
		{name: "system", level: ServiceLevelSystem, want: ServiceLevelSystem},
		{name: "allusers", level: ServiceLevelAllUsers, want: ServiceLevelAllUsers},
		{name: "user", level: ServiceLevelUser, want: ServiceLevelUser},
		{name: "legacy UserService", userService: true, want: ServiceLevelUser},
		{name: "UserService with user", level: ServiceLevelUser, userService: true, want: ServiceLevelUser},
		{name: "UserService with system", level: ServiceLevelSystem, userService: true, want: ServiceLevelSystem},
		{name: "UserService with allusers", level: ServiceLevelAllUsers, userService: true, want: ServiceLevelAllUsers},
		{name: "UserService with invalid", level: "bogus", userService: true, wantErr: true},
		{name: "invalid", level: "bogus", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{ServiceLevel: tt.level, Option: KeyValue{optionUserService: tt.userService}}
			got, err := c.userServiceLevel()
			if (err != nil) != tt.wantErr {
				t.Fatalf("userServiceLevel() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("userServiceLevel() = %q, want %q", got, tt.want)
			}
		})
	}
}
