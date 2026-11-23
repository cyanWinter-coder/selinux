package selinux

import (
	"errors"
	"testing"
)

// assertModuleError fails the test unless err is a *ModuleError of kind.
func assertModuleError(t *testing.T, err error, kind ModuleErrorKind) {
	t.Helper()
	var moduleErr *ModuleError
	if !errors.As(err, &moduleErr) {
		t.Fatalf("expected *ModuleError, got %T: %v", err, err)
	}
	if moduleErr.Kind != kind {
		t.Fatalf("expected error kind %d, got %d (%v)", kind, moduleErr.Kind, err)
	}
}
