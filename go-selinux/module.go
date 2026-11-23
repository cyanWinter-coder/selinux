package selinux

import (
	stderrors "errors"
	"os"
	"slices"
	"sync"
)

// ModuleErrorKind classifies an error returned while loading SELinux policy
// modules.
type ModuleErrorKind int

const (
	// KindInvalidInput means the caller supplied malformed module
	// specifications (unknown names, empty paths, duplicates or unreadable
	// module files). No system state was changed.
	KindInvalidInput ModuleErrorKind = iota + 1
	// KindUnavailable means SELinux policy management is not usable on this
	// system, for example because SELinux is disabled or the semodule tool is
	// missing. No system state was changed.
	KindUnavailable
	// KindSystemRejected means the system refused the operation while
	// loading a module. For batch loads, every module of the batch has been
	// rolled back and the policy is back to its pre-load state.
	KindSystemRejected
	// KindRollbackFailed means the system refused a module load and the
	// subsequent rollback failed as well. The policy may be left in a partial
	// state and must be repaired manually.
	KindRollbackFailed
)

// Sentinel errors backing the [ModuleError] kinds. Use [errors.Is] to match
// them; inspect the [ModuleError] for details.
var (
	// ErrModuleInvalidInput wraps [ModuleError] values of kind
	// [KindInvalidInput].
	ErrModuleInvalidInput = stderrors.New("invalid SELinux module input")
	// ErrSELinuxUnavailable wraps [ModuleError] values of kind
	// [KindUnavailable].
	ErrSELinuxUnavailable = stderrors.New("SELinux policy management is unavailable")
	// ErrModuleRejected wraps [ModuleError] values of kind
	// [KindSystemRejected].
	ErrModuleRejected = stderrors.New("SELinux rejected the policy module operation")
	// ErrModuleRollbackFailed wraps [ModuleError] values of kind
	// [KindRollbackFailed].
	ErrModuleRollbackFailed = stderrors.New("rollback of SELinux policy modules failed")
)

// ModuleError describes a failure while loading one or more SELinux policy
// modules.
type ModuleError struct {
	// Err is the underlying error.
	Err error
	// Module is the name of the module the failure is attributed to. It is
	// empty when the failure is not tied to a particular module.
	Module string
	// Kind classifies the failure.
	Kind ModuleErrorKind
}

func (e *ModuleError) Error() string {
	var kind string
	switch e.Kind {
	case KindInvalidInput:
		kind = ErrModuleInvalidInput.Error()
	case KindUnavailable:
		kind = ErrSELinuxUnavailable.Error()
	case KindSystemRejected:
		kind = ErrModuleRejected.Error()
	case KindRollbackFailed:
		kind = ErrModuleRollbackFailed.Error()
	default:
		kind = "unknown SELinux module error"
	}
	if e.Module != "" {
		kind += ": module " + e.Module
	}
	if e.Err != nil {
		kind += ": " + e.Err.Error()
	}
	return kind
}

// Unwrap supports both errors.Is/As against the kind's sentinel error and
// traversal of the joined underlying errors (for example the rollback errors
// plus the original load rejection).
func (e *ModuleError) Unwrap() []error {
	var sentinel error
	switch e.Kind {
	case KindInvalidInput:
		sentinel = ErrModuleInvalidInput
	case KindUnavailable:
		sentinel = ErrSELinuxUnavailable
	case KindSystemRejected:
		sentinel = ErrModuleRejected
	case KindRollbackFailed:
		sentinel = ErrModuleRollbackFailed
	}
	if e.Err == nil {
		return []error{sentinel}
	}
	if sentinel == nil {
		return []error{e.Err}
	}
	return []error{sentinel, e.Err}
}

// ModuleSpec identifies a SELinux policy module to load. Name is the policy
// module name as known to the policy store; Path is the location of the
// compiled policy module package.
type ModuleSpec struct {
	// Name is the policy module name used for tracking and rollback.
	Name string
	// Path is the path of the compiled policy module package.
	Path string
}

// moduleBackend is the system-specific mechanism used to manage SELinux policy
// modules. The real backend shells out to semodule; tests replace it with a
// fake.
type moduleBackend interface {
	// available reports whether policy module management can be used at all.
	available() error
	// listInstalled returns the names of the modules currently present in
	// the policy store.
	listInstalled() ([]string, error)
	// install loads the module package at path under the given name.
	install(mod ModuleSpec) error
	// remove removes a previously installed module by name.
	remove(name string) error
}

var (
	// newModuleBackend builds the system-specific backend. Overridden by
	// platform files and by tests.
	newModuleBackend = defaultModuleBackend

	// moduleCommitMu serializes all module commits so concurrent batches
	// cannot interleave their load and rollback operations.
	moduleCommitMu sync.Mutex
)

// LoadModule loads a single SELinux policy module. It is equivalent to a
// one-element [LoadModules] transaction: a failed load leaves the policy
// unchanged and the returned error follows the same classification.
func LoadModule(name, path string) error {
	return loadModules([]ModuleSpec{{Name: name, Path: path}})
}

// LoadModules loads a batch of SELinux policy modules as one transaction.
//
// All module specifications are validated before the policy store is touched:
// names must be non-empty and well formed, paths must be readable and names
// must not be duplicated within the batch. The modules are then loaded in a
// deterministic order (sorted by name). If any module is rejected by the
// system, every module of the batch is removed again and the policy is
// restored to its pre-load state.
//
// Concurrent calls are serialized; each call only affects the modules it
// declares. The returned error is nil on success or a [ModuleError] whose
// Kind distinguishes invalid input, an unavailable SELinux, a system
// rejection that was fully rolled back and a failed rollback.
func LoadModules(modules []ModuleSpec) error {
	return loadModules(modules)
}

// loadModules implements [LoadModules]. It holds moduleCommitMu for the whole
// transaction so concurrent batches are serialized.
func loadModules(modules []ModuleSpec) error {
	moduleCommitMu.Lock()
	defer moduleCommitMu.Unlock()

	backend := newModuleBackend()

	if err := preflightModules(backend, modules); err != nil {
		return err
	}

	// Copy before sorting so the caller's slice is not reordered.
	batch := slices.Clone(modules)
	slices.SortFunc(batch, func(a, b ModuleSpec) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})

	installed, err := listInstalledSet(backend)
	if err != nil {
		return &ModuleError{Kind: KindSystemRejected, Err: err}
	}

	loaded := make([]string, 0, len(batch))
	for _, mod := range batch {
		// Record the module before installing: an install may change the
		// store and still report failure, in which case it must be rolled
		// back as well.
		loaded = append(loaded, mod.Name)
		if err := backend.install(mod); err != nil {
			return rollbackModules(backend, mod.Name, err, loaded, installed)
		}
	}
	return nil
}

// preflightModules runs every check that must pass before the policy store is
// modified: SELinux availability, per-specification validation and
// duplicate detection within the batch.
func preflightModules(backend moduleBackend, modules []ModuleSpec) error {
	if err := backend.available(); err != nil {
		return &ModuleError{Kind: KindUnavailable, Err: err}
	}

	if len(modules) == 0 {
		return &ModuleError{Kind: KindInvalidInput, Err: stderrors.New("no modules specified")}
	}

	seen := make(map[string]struct{}, len(modules))
	for _, mod := range modules {
		if mod.Name == "" {
			return &ModuleError{Kind: KindInvalidInput, Err: stderrors.New("module name must not be empty")}
		}
		if !validModuleName(mod.Name) {
			return &ModuleError{
				Kind: KindInvalidInput, Module: mod.Name,
				Err: stderrors.New("module name contains invalid characters"),
			}
		}
		if mod.Path == "" {
			return &ModuleError{
				Kind: KindInvalidInput, Module: mod.Name,
				Err: ErrEmptyPath,
			}
		}
		if _, ok := seen[mod.Name]; ok {
			return &ModuleError{
				Kind: KindInvalidInput, Module: mod.Name,
				Err: stderrors.New("duplicate module in batch"),
			}
		}
		seen[mod.Name] = struct{}{}

		file, err := os.Open(mod.Path)
		if err != nil {
			return &ModuleError{Kind: KindInvalidInput, Module: mod.Name, Err: err}
		}
		_ = file.Close()
	}
	return nil
}

// validModuleName reports whether name is a plausible policy module name.
// Valid names start with an alphanumeric character or underscore and
// otherwise contain alphanumeric characters, underscores, dots and hyphens.
func validModuleName(name string) bool {
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
		case i > 0 && (r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// listInstalledSet returns the names of the modules already present in the
// policy store as a set.
func listInstalledSet(backend moduleBackend) (map[string]struct{}, error) {
	names, err := backend.listInstalled()
	if err != nil {
		return nil, err
	}
	installed := make(map[string]struct{}, len(names))
	for _, name := range names {
		installed[name] = struct{}{}
	}
	return installed, nil
}

// rollbackModules removes the batch modules that were loaded, or whose
// installation was in flight, before the failure, in reverse load order.
// Modules that were already installed before the batch are left alone:
// removing them would undo unrelated state and their original package is not
// available to restore an older version.
func rollbackModules(backend moduleBackend, failedName string, loadErr error,
	loaded []string, installed map[string]struct{},
) error {
	var rollbackErrs []error
	for i := len(loaded) - 1; i >= 0; i-- {
		name := loaded[i]
		if _, preExisting := installed[name]; preExisting {
			continue
		}
		if err := backend.remove(name); err != nil {
			rollbackErrs = append(rollbackErrs, &ModuleError{
				Kind: KindRollbackFailed, Module: name, Err: err,
			})
		}
	}

	loadFailure := &ModuleError{Kind: KindSystemRejected, Module: failedName, Err: loadErr}
	if len(rollbackErrs) == 0 {
		return loadFailure
	}
	return &ModuleError{
		Kind: KindRollbackFailed,
		Err:  stderrors.Join(append(rollbackErrs, loadFailure)...),
	}
}
