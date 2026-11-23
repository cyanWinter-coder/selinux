//go:build !linux

package selinux

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadModulesUnavailableOnNonLinux(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.pp")
	if err := os.WriteFile(path, []byte("policy module"), 0o600); err != nil {
		t.Fatalf("write module file: %v", err)
	}

	err := LoadModules([]ModuleSpec{{Name: "module", Path: path}})
	assertModuleError(t, err, KindUnavailable)
	if !errors.Is(err, ErrSELinuxUnavailable) {
		t.Fatalf("expected errors.Is(err, ErrSELinuxUnavailable), got %v", err)
	}

	if err := LoadModule("module", path); err == nil {
		t.Fatal("LoadModule must fail on platforms without SELinux support")
	} else if !errors.Is(err, ErrSELinuxUnavailable) {
		t.Fatalf("LoadModule error = %v, want ErrSELinuxUnavailable", err)
	}
}
