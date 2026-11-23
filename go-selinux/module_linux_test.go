package selinux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// fakeModuleBackend is an in-memory moduleBackend for transaction tests.
// All state is guarded by mu so concurrent batches can be exercised safely.
//
//nolint:govet // field alignment: sync.Mutex contains an unsafe.Pointer that the analyzer cannot place optimally.
type fakeModuleBackend struct {
	installOrder   []string
	removeOrder    []string
	availableErr   error
	listErr        error
	installErr     map[string]error
	removeErr      map[string]error
	installed      map[string]struct{}
	mu             sync.Mutex
	installCalls   int
	listCalls      int
	availableCalls int
}

func newFakeBackend() *fakeModuleBackend {
	return &fakeModuleBackend{
		installErr: map[string]error{},
		removeErr:  map[string]error{},
		installed:  map[string]struct{}{},
	}
}

func (f *fakeModuleBackend) available() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.availableCalls++
	return f.availableErr
}

func (f *fakeModuleBackend) listInstalled() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	names := make([]string, 0, len(f.installed))
	for name := range f.installed {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

func (f *fakeModuleBackend) install(mod ModuleSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installCalls++
	// Record the attempt even when the install fails, mirroring a backend
	// whose operation may reach the policy store before returning an error.
	f.installOrder = append(f.installOrder, mod.Name)
	if err := f.installErr[mod.Name]; err != nil {
		return err
	}
	f.installed[mod.Name] = struct{}{}
	return nil
}

func (f *fakeModuleBackend) remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.removeErr[name]; err != nil {
		return err
	}
	// A module that never reached the store has nothing to remove; the
	// transaction's rollback of it is a successful no-op.
	if _, ok := f.installed[name]; !ok {
		f.removeOrder = append(f.removeOrder, name)
		return nil
	}
	f.removeOrder = append(f.removeOrder, name)
	delete(f.installed, name)
	return nil
}

// withFakeBackend swaps the package backend factory for backend for the
// duration of the test and restores it afterwards.
func withFakeBackend(t *testing.T, backend moduleBackend) {
	t.Helper()
	original := newModuleBackend
	newModuleBackend = func() moduleBackend { return backend }
	t.Cleanup(func() { newModuleBackend = original })
}

// writeModuleFile creates an empty, readable module package file and returns
// its path.
func writeModuleFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name+".pp")
	if err := os.WriteFile(path, []byte("policy module "+name), 0o600); err != nil {
		t.Fatalf("write module file %s: %v", path, err)
	}
	return path
}

func moduleSpecs(t *testing.T, dir string, names ...string) []ModuleSpec {
	t.Helper()
	mods := make([]ModuleSpec, 0, len(names))
	for _, name := range names {
		mods = append(mods, ModuleSpec{Name: name, Path: writeModuleFile(t, dir, name)})
	}
	return mods
}

func TestLoadModulesSuccess(t *testing.T) {
	fake := newFakeBackend()
	withFakeBackend(t, fake)

	mods := moduleSpecs(t, t.TempDir(), "zebra", "alpha", "mid")
	if err := LoadModules(mods); err != nil {
		t.Fatalf("LoadModules failed: %v", err)
	}

	wantOrder := []string{"alpha", "mid", "zebra"}
	if !slices.Equal(fake.installOrder, wantOrder) {
		t.Fatalf("modules loaded in %v, want %v", fake.installOrder, wantOrder)
	}
	for _, name := range wantOrder {
		if _, ok := fake.installed[name]; !ok {
			t.Errorf("module %q not present after successful load", name)
		}
	}
}

func TestLoadModulesEmptyBatch(t *testing.T) {
	fake := newFakeBackend()
	withFakeBackend(t, fake)

	err := LoadModules(nil)
	assertModuleError(t, err, KindInvalidInput)
	if !errors.Is(err, ErrModuleInvalidInput) {
		t.Errorf("expected errors.Is(err, ErrModuleInvalidInput), got %v", err)
	}
	if fake.installCalls != 0 {
		t.Errorf("expected no install calls, got %d", fake.installCalls)
	}
}

func TestLoadModulesPreflightValidation(t *testing.T) {
	tests := []struct {
		prepare func(dir string) []ModuleSpec
		name    string
	}{
		{
			name: "empty module name",
			prepare: func(dir string) []ModuleSpec {
				return []ModuleSpec{{Name: "", Path: writeModuleFile(t, dir, "a")}}
			},
		},
		{
			name: "invalid module name",
			prepare: func(dir string) []ModuleSpec {
				return []ModuleSpec{{Name: "bad/name", Path: writeModuleFile(t, dir, "module-a")}}
			},
		},
		{
			name: "empty path",
			prepare: func(string) []ModuleSpec {
				return []ModuleSpec{{Name: "nopath", Path: ""}}
			},
		},
		{
			name: "unreadable path",
			prepare: func(string) []ModuleSpec {
				return []ModuleSpec{{Name: "missing", Path: filepath.Join(t.TempDir(), "does-not-exist.pp")}}
			},
		},
		{
			name: "duplicate module names",
			prepare: func(dir string) []ModuleSpec {
				mods := moduleSpecs(t, dir, "dup", "other")
				mods = append(mods, ModuleSpec{Name: "dup", Path: writeModuleFile(t, dir, "dup-copy")})
				return mods
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeBackend()
			withFakeBackend(t, fake)

			err := LoadModules(tt.prepare(t.TempDir()))
			assertModuleError(t, err, KindInvalidInput)
			if !errors.Is(err, ErrModuleInvalidInput) {
				t.Errorf("expected errors.Is(err, ErrModuleInvalidInput), got %v", err)
			}
			if fake.installCalls != 0 || fake.listCalls != 0 {
				t.Errorf("preflight failure must not touch the policy store, got installs=%d lists=%d",
					fake.installCalls, fake.listCalls)
			}
		})
	}
}

func TestLoadModulesUnavailable(t *testing.T) {
	fake := newFakeBackend()
	fake.availableErr = errors.New("semodule missing")
	withFakeBackend(t, fake)

	err := LoadModules(moduleSpecs(t, t.TempDir(), "a", "b"))
	assertModuleError(t, err, KindUnavailable)
	if !errors.Is(err, ErrSELinuxUnavailable) {
		t.Errorf("expected errors.Is(err, ErrSELinuxUnavailable), got %v", err)
	}
	if fake.installCalls != 0 {
		t.Errorf("expected no install calls, got %d", fake.installCalls)
	}
}

func TestLoadModulesSystemRejectedRollsBack(t *testing.T) {
	fake := newFakeBackend()
	// "alpha" and "mid" load, "zebra" is rejected by the system.
	fake.installErr["zebra"] = errors.New("invalid module syntax")
	withFakeBackend(t, fake)

	err := LoadModules(moduleSpecs(t, t.TempDir(), "zebra", "alpha", "mid"))
	assertModuleError(t, err, KindSystemRejected)
	if !errors.Is(err, ErrModuleRejected) {
		t.Errorf("expected errors.Is(err, ErrModuleRejected), got %v", err)
	}
	var moduleErr *ModuleError
	if !errors.As(err, &moduleErr) {
		t.Fatalf("expected *ModuleError, got %T: %v", err, err)
	}
	if moduleErr.Module != "zebra" {
		t.Errorf("failure attributed to %q, want %q", moduleErr.Module, "zebra")
	}

	// Sorted load order means alpha and mid were installed before zebra was
	// rejected; the failed attempt is recorded so rollback still covers it.
	if !slices.Equal(fake.installOrder, []string{"alpha", "mid", "zebra"}) {
		t.Fatalf("unexpected install order: %v", fake.installOrder)
	}
	// Rollback removes all attempted modules in reverse order. The zebra
	// install never reached the fake store, so its removal is a no-op.
	if !slices.Equal(fake.removeOrder, []string{"zebra", "mid", "alpha"}) {
		t.Fatalf("unexpected rollback order: %v, want [zebra mid alpha]", fake.removeOrder)
	}
	if len(fake.installed) != 0 {
		t.Errorf("policy store not restored, still contains %v", fake.installed)
	}
}

func TestLoadModulesRollbackFailure(t *testing.T) {
	fake := newFakeBackend()
	fake.installErr["zebra"] = errors.New("system rejected load")
	// Rollback of "mid" fails as well.
	fake.removeErr["mid"] = errors.New("store locked")
	withFakeBackend(t, fake)

	err := LoadModules(moduleSpecs(t, t.TempDir(), "alpha", "mid", "zebra"))
	assertModuleError(t, err, KindRollbackFailed)
	if !errors.Is(err, ErrModuleRollbackFailed) {
		t.Errorf("expected errors.Is(err, ErrModuleRollbackFailed), got %v", err)
	}
	// The original rejection must remain discoverable in the joined error.
	if !errors.Is(err, ErrModuleRejected) {
		t.Errorf("rollback error should still wrap the original rejection, got %v", err)
	}
	var moduleErr *ModuleError
	if !errors.As(err, &moduleErr) {
		t.Fatalf("expected *ModuleError, got %T: %v", err, err)
	}
	if moduleErr.Err == nil || !errors.Is(moduleErr.Err, ErrModuleRejected) {
		t.Errorf("rollback error must retain the load failure, got %v", moduleErr.Err)
	}

	// "alpha" was rolled back; "mid" remains because its removal failed.
	if _, ok := fake.installed["alpha"]; ok {
		t.Errorf("module alpha should have been removed")
	}
	if _, ok := fake.installed["mid"]; !ok {
		t.Errorf("module mid should remain after failed removal")
	}
}

func TestLoadModulesRollbackKeepsPreExistingModules(t *testing.T) {
	fake := newFakeBackend()
	// "alpha" already exists in the store before the batch and is upgraded in
	// place; rollback must not remove it.
	fake.installed["alpha"] = struct{}{}
	fake.installErr["zebra"] = errors.New("system rejected load")
	withFakeBackend(t, fake)

	err := LoadModules(moduleSpecs(t, t.TempDir(), "alpha", "zebra"))
	assertModuleError(t, err, KindSystemRejected)
	if _, ok := fake.installed["alpha"]; !ok {
		t.Errorf("pre-existing module alpha must not be removed during rollback")
	}
	// Only the failed batch module is touched during rollback; the
	// pre-existing alpha is skipped.
	if !slices.Equal(fake.removeOrder, []string{"zebra"}) {
		t.Errorf("unexpected removals: %v, want [zebra]", fake.removeOrder)
	}
	if _, ok := fake.installed["zebra"]; ok {
		t.Errorf("failed module zebra must not remain in the store")
	}
}

func TestLoadModulesListFailureIsSystemRejection(t *testing.T) {
	fake := newFakeBackend()
	fake.listErr = errors.New("cannot query policy store")
	withFakeBackend(t, fake)

	err := LoadModules(moduleSpecs(t, t.TempDir(), "alpha"))
	assertModuleError(t, err, KindSystemRejected)
	if fake.installCalls != 0 {
		t.Errorf("expected no install calls, got %d", fake.installCalls)
	}
}

func TestLoadModuleSingleCompatibility(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fake := newFakeBackend()
		withFakeBackend(t, fake)

		path := writeModuleFile(t, t.TempDir(), "solo")
		if err := LoadModule("solo", path); err != nil {
			t.Fatalf("LoadModule failed: %v", err)
		}
		if !slices.Equal(fake.installOrder, []string{"solo"}) {
			t.Fatalf("unexpected install order: %v", fake.installOrder)
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		fake := newFakeBackend()
		withFakeBackend(t, fake)

		err := LoadModule("", filepath.Join(t.TempDir(), "x.pp"))
		assertModuleError(t, err, KindInvalidInput)
		if fake.installCalls != 0 {
			t.Errorf("expected no install calls, got %d", fake.installCalls)
		}
	})

	t.Run("system error with rollback", func(t *testing.T) {
		fake := newFakeBackend()
		fake.installErr["solo"] = errors.New("permission denied")
		withFakeBackend(t, fake)

		err := LoadModule("solo", writeModuleFile(t, t.TempDir(), "solo"))
		assertModuleError(t, err, KindSystemRejected)
		if len(fake.installed) != 0 {
			t.Errorf("store must be empty after rolled back single load, got %v", fake.installed)
		}
	})

	t.Run("rollback failure", func(t *testing.T) {
		fake := newFakeBackend()
		withFakeBackend(t, fake)

		// An install that mutates the store and then reports failure gives
		// the transaction something to roll back; the failing removal must
		// surface as KindRollbackFailed rather than a plain rejection.
		fake.removeErr["solo"] = errors.New("removal denied")
		wrapped := &partialInstallBackend{
			fake:      fake,
			failName:  "solo",
			failErr:   errors.New("kernel rejected policy"),
			removeErr: fake.removeErr["solo"],
		}
		withFakeBackend(t, wrapped)

		err := LoadModule("solo", writeModuleFile(t, t.TempDir(), "solo"))
		assertModuleError(t, err, KindRollbackFailed)
	})
}

// partialInstallBackend models an install that mutates the store and then
// reports failure, so the transaction has something to roll back.
type partialInstallBackend struct {
	fake      *fakeModuleBackend
	failErr   error
	removeErr error
	failName  string
}

func (p *partialInstallBackend) available() error { return p.fake.available() }

func (p *partialInstallBackend) listInstalled() ([]string, error) {
	return p.fake.listInstalled()
}

func (p *partialInstallBackend) install(mod ModuleSpec) error {
	p.fake.mu.Lock()
	defer p.fake.mu.Unlock()
	p.fake.installCalls++
	p.fake.installOrder = append(p.fake.installOrder, mod.Name)
	p.fake.installed[mod.Name] = struct{}{}
	if mod.Name == p.failName {
		return p.failErr
	}
	return nil
}

func (p *partialInstallBackend) remove(name string) error {
	if err := p.removeErr; err != nil && name == p.failName {
		return err
	}
	return p.fake.remove(name)
}

func TestLoadModulesConcurrentBatchesSerialized(t *testing.T) {
	fake := newFakeBackend()
	withFakeBackend(t, fake)

	// Track the maximum number of in-flight transactions observed by the
	// backend; serialization requires it to never exceed one.
	var inflight, maxInflight int
	var inflightMu sync.Mutex
	tracking := &trackingBackend{
		fake: fake,
		onInstall: func() {
			inflightMu.Lock()
			defer inflightMu.Unlock()
			inflight++
			if inflight > maxInflight {
				maxInflight = inflight
			}
		},
		onInstallDone: func() {
			inflightMu.Lock()
			defer inflightMu.Unlock()
			inflight--
		},
	}
	withFakeBackend(t, tracking)

	const batches = 8
	var wg sync.WaitGroup
	for i := range batches {
		dir := t.TempDir()
		mods := moduleSpecs(t, dir, fmt.Sprintf("mod-%d-a", i), fmt.Sprintf("mod-%d-b", i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := LoadModules(mods); err != nil {
				t.Errorf("batch %d failed: %v", i, err)
			}
		}()
	}
	wg.Wait()

	if maxInflight > 1 {
		t.Errorf("batches overlapped: max inflight installs = %d, want <= 1", maxInflight)
	}
	if len(fake.installed) != batches*2 {
		t.Errorf("expected %d installed modules, got %d", batches*2, len(fake.installed))
	}
}

// trackingBackend wraps fakeModuleBackend and records install concurrency.
type trackingBackend struct {
	fake          *fakeModuleBackend
	onInstall     func()
	onInstallDone func()
}

func (t2 *trackingBackend) available() error { return t2.fake.available() }

func (t2 *trackingBackend) listInstalled() ([]string, error) {
	return t2.fake.listInstalled()
}

func (t2 *trackingBackend) install(mod ModuleSpec) error {
	t2.onInstall()
	defer t2.onInstallDone()
	return t2.fake.install(mod)
}

func (t2 *trackingBackend) remove(name string) error {
	return t2.fake.remove(name)
}

func TestLoadModulesOnlyAffectsDeclaredModules(t *testing.T) {
	fake := newFakeBackend()
	// Unrelated modules exist in the store and must survive every batch.
	fake.installed["unrelated-one"] = struct{}{}
	fake.installed["unrelated-two"] = struct{}{}
	withFakeBackend(t, fake)

	if err := LoadModules(moduleSpecs(t, t.TempDir(), "mine-a", "mine-b")); err != nil {
		t.Fatalf("LoadModules failed: %v", err)
	}
	for _, name := range []string{"unrelated-one", "unrelated-two"} {
		if _, ok := fake.installed[name]; !ok {
			t.Errorf("unrelated module %q was touched by the batch", name)
		}
	}
	if len(fake.removeOrder) != 0 {
		t.Errorf("successful batch must not remove anything, got %v", fake.removeOrder)
	}
}
