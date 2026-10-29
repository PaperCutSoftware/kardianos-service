package service

import (
	"strings"
	"testing"
)

func TestServiceLevelUnknownDoesNotResolve(t *testing.T) {
	c := &Config{ServiceLevel: "bogus"}
	if _, err := c.serviceLevel(); err == nil || !strings.Contains(err.Error(), `"bogus"`) {
		t.Errorf("serviceLevel(bogus) error = %v, want error naming the value", err)
	}
}
