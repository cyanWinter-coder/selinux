package label

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/opencontainers/selinux/go-selinux"
)

// ErrLabelTransitionDenied is returned when the kernel (SELinux policy)
// refuses a process label transition. A denial is a definitive policy
// decision, not a transient condition: it must be surfaced to the caller and
// never retried or classified as a lightweight temporary error.
var ErrLabelTransitionDenied = errors.New("SELinux process label transition denied by policy")

// transitionDeniedError wraps a kernel policy refusal so that it matches both
// [ErrLabelTransitionDenied] (the hard policy decision) and the original
// permission error (EACCES/EPERM) via errors.Is/errors.As.
type transitionDeniedError struct {
	cause error
}

func (e *transitionDeniedError) Error() string {
	return fmt.Sprintf("%v: %v", ErrLabelTransitionDenied, e.cause)
}

func (e *transitionDeniedError) Unwrap() []error {
	return []error{ErrLabelTransitionDenied, e.cause}
}

// processLabelMu serializes every process (attr/exec) label transition
// performed through this package. SELinux exec labels are per-thread kernel
// state, and the Go runtime may schedule different goroutines on different
// threads, so without this lock one goroutine could read or overwrite the
// exec label another goroutine is in the middle of switching. The critical
// section runs while the calling goroutine is pinned to its OS thread (see
// [SetProcessLabel]), which makes the whole transition an atomic, rollback-able
// boundary other goroutines cannot enter.
var processLabelMu sync.Mutex

// Test seams. They default to the real selinux package calls and are only
// reassigned from tests so the rollback logic can be exercised on machines
// where SELinux is disabled or unavailable.
var (
	readExecLabel  = selinux.ExecLabel
	writeExecLabel = selinux.SetExecLabel
)

// SetProcessLabel arranges for the kernel to assign processLabel to the next
// program executed by the calling process (it writes the per-thread
// attr/exec label). It is a rollback-able transaction with a clearly defined
// transition boundary:
//
//   - The calling goroutine is pinned to its OS thread for the duration of
//     the call, and a package-wide mutex prevents any other goroutine from
//     entering a process label transition concurrently. Together these
//     guarantee the exec label cannot be observed half-switched from another
//     thread.
//   - The caller's current exec label is captured before any change. If
//     writing processLabel fails, the previous label is restored. If that
//     restoration also fails, the two failures are combined with
//     [errors.Join] and returned, so no partial state is hidden.
//   - A policy refusal (EACCES/EPERM) is wrapped with
//     [ErrLabelTransitionDenied]: it is a hard, definitive error rather than
//     a transient one.
//
// Because the label applies to the subsequent execve, callers must keep the
// goroutine pinned (runtime.LockOSThread) from SetProcessLabel until the
// program has been executed, so another goroutine cannot migrate onto the
// labeled thread.
//
// SetProcessLabel owns only the process (attr/exec) label used by the next
// execve. The file-creation label (attr/fscreate) is a distinct, independent
// responsibility managed by [SetFileCreateLabel]; the two are never mixed, so
// a failure in one leaves the other untouched.
//
// When SELinux is unavailable or disabled this is a no-op that touches no
// kernel state and never leaves partial state behind.
func SetProcessLabel(processLabel string) error {
	if !selinux.GetEnabled() {
		return nil
	}
	return setProcessLabelTransaction(processLabel)
}

// setProcessLabelTransaction runs the actual pinned, serialized transition.
// It is split from [SetProcessLabel] so tests can drive the rollback paths
// directly through the injected seams regardless of whether SELinux is
// enabled on the host.
func setProcessLabelTransaction(processLabel string) error {
	// Pin before taking the mutex: every kernel access below must hit the
	// same thread, and the goroutine must not be migrated while the exec
	// label it set remains pending for the next execve.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	processLabelMu.Lock()
	defer processLabelMu.Unlock()

	// Capture the label that must be restored if the switch fails.
	prevLabel, err := readExecLabel()
	if err != nil {
		return fmt.Errorf("reading current SELinux process label: %w", err)
	}

	if err := writeExecLabel(processLabel); err != nil {
		// The new label was not applied. Restore what was there before the
		// transition so the thread never keeps an unintended exec label.
		if restoreErr := writeExecLabel(prevLabel); restoreErr != nil {
			return errors.Join(
				fmt.Errorf("setting SELinux process label %q: %w", processLabel, classifyTransitionError(err)),
				fmt.Errorf("restoring previous SELinux process label %q after failed transition: %w", prevLabel, restoreErr),
			)
		}
		return fmt.Errorf("setting SELinux process label %q: %w", processLabel, classifyTransitionError(err))
	}

	return nil
}

// classifyTransitionError marks kernel policy refusals so callers can tell a
// definitive denial apart from ordinary, potentially transient, I/O errors.
// os.ErrPermission matches both EACCES and EPERM returned by the kernel.
func classifyTransitionError(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return &transitionDeniedError{cause: err}
	}
	return err
}
