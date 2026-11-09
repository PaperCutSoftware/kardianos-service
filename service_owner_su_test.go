//go:build su && (darwin || linux)

package service

import "testing"

func TestOwnershipRootOwned(t *testing.T) {
	if _, err := checkExecutableOwnership("/bin/sh"); err != nil {
		t.Error(err)
	}
}
