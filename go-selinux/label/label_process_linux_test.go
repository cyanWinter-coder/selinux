package label

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/opencontainers/selinux/go-selinux"
)

// fakeExecLabel is an in-memory stand-in for the per-thread attr/exec label.
// Reads and writes go through the package's test seams so the rollback
// transaction can be exercised even when SELinux is disabled on the host.
type fakeExecLabel struct {
	mu       sync.Mutex
	current  string
	reads    int
	writes   []string
	failNext map[string]error // label write that should fail, keyed by value written
}

func newFakeExecLabel(initial string) *fakeExecLabel {
	return &fakeExecLabel{
		current:  initial,
		failNext: make(map[string]error),
	}
}

func (f *fakeExecLabel) read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.current, nil
}

func (f *fakeExecLabel) write(val string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext[val]; err != nil {
		return err
	}
	f.writes = append(f.writes, val)
	f.current = val
	return nil
}

// snapshot returns the writes observed so far and the label currently stored.
func (f *fakeExecLabel) snapshot() ([]string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.writes))
	copy(out, f.writes)
	return out, f.current
}

// withSeams swaps the package test seams for the duration of the test.
func withSeams(t *testing.T, f *fakeExecLabel) {
	t.Helper()
	origRead, origWrite := readExecLabel, writeExecLabel
	readExecLabel = f.read
	writeExecLabel = f.write
	t.Cleanup(func() {
		readExecLabel, writeExecLabel = origRead, origWrite
	})
}

func TestSetProcessLabel_DisabledIsNoop(t *testing.T) {
	// SELinux is unavailable/disabled: the call must not touch any kernel
	// state and must not produce a partial transition.
	if selinux.GetEnabled() {
		t.Skip("SELinux enabled; no-op path not applicable on this host.")
	}
	f := newFakeExecLabel("orig_u:orig_r:orig_t:s0")
	withSeams(t, f)

	if err := SetProcessLabel("system_u:object_r:container_t:s0:c1,c2"); err != nil {
		t.Fatalf("SetProcessLabel on disabled SELinux: %v", err)
	}
	writes, current := f.snapshot()
	if len(writes) != 0 || current != "orig_u:orig_r:orig_t:s0" {
		t.Fatalf("expected no kernel interaction, got writes=%v current=%q", writes, current)
	}
}

func TestSetProcessLabel_Success(t *testing.T) {
	const (
		oldLabel = "system_u:system_r:spc_t:s0"
		newLabel = "system_u:object_r:container_t:s0:c1,c2"
	)
	f := newFakeExecLabel(oldLabel)
	withSeams(t, f)

	if err := setProcessLabelTransaction(newLabel); err != nil {
		t.Fatalf("SetProcessLabel failed: %v", err)
	}
	writes, current := f.snapshot()
	if len(writes) != 1 || writes[0] != newLabel {
		t.Fatalf("expected single write of %q, got %v", newLabel, writes)
	}
	if current != newLabel {
		t.Fatalf("expected current label %q, got %q", newLabel, current)
	}
}

func TestSetProcessLabel_EmptyLabelClearsExecLabel(t *testing.T) {
	const oldLabel = "system_u:system_r:spc_t:s0"
	f := newFakeExecLabel(oldLabel)
	withSeams(t, f)

	// An empty label means "return to default"; it must be written through,
	// not swallowed.
	if err := setProcessLabelTransaction(""); err != nil {
		t.Fatalf("SetProcessLabel(\"\") failed: %v", err)
	}
	writes, current := f.snapshot()
	if len(writes) != 1 || writes[0] != "" {
		t.Fatalf("expected single empty write, got %v", writes)
	}
	if current != "" {
		t.Fatalf("expected cleared label, got %q", current)
	}
}

func TestSetProcessLabel_FailureRestoresPreviousLabel(t *testing.T) {
	const (
		oldLabel = "system_u:system_r:spc_t:s0"
		newLabel = "system_u:object_r:container_t:s0:c1,c2"
	)
	denied := fmt.Errorf("write attr/exec: %w", os.ErrPermission)
	f := newFakeExecLabel(oldLabel)
	f.failNext[newLabel] = denied
	withSeams(t, f)

	err := setProcessLabelTransaction(newLabel)
	if err == nil {
		t.Fatal("expected transition to fail, got nil")
	}
	// A policy refusal must be surfaced as the hard, non-transient sentinel...
	if !errors.Is(err, ErrLabelTransitionDenied) {
		t.Fatalf("expected ErrLabelTransitionDenied, got %v", err)
	}
	// ...and the underlying permission cause must remain reachable.
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("underlying permission error should be unwrappable, got %v", err)
	}

	// Rollback: the previous label is written back and ends up current.
	writes, current := f.snapshot()
	wantWrites := []string{oldLabel}
	if len(writes) != 1 || writes[0] != wantWrites[0] {
		t.Fatalf("expected rollback write %v, got %v", wantWrites, writes)
	}
	if current != oldLabel {
		t.Fatalf("expected restored label %q, got %q", oldLabel, current)
	}
}

func TestSetProcessLabel_NonPermissionErrorAlsoRollsBack(t *testing.T) {
	const (
		oldLabel = "system_u:system_r:spc_t:s0"
		newLabel = "system_u:object_r:container_t:s0:c9,c9"
	)
	ioErr := errors.New("temporary kernel i/o error")
	f := newFakeExecLabel(oldLabel)
	f.failNext[newLabel] = ioErr
	withSeams(t, f)

	err := setProcessLabelTransaction(newLabel)
	if err == nil {
		t.Fatal("expected transition to fail, got nil")
	}
	// An ordinary error must not be mislabeled as a policy denial.
	if errors.Is(err, ErrLabelTransitionDenied) {
		t.Fatalf("ordinary error must not be classified as denial, got %v", err)
	}
	if !errors.Is(err, ioErr) {
		t.Fatalf("underlying error should be reachable, got %v", err)
	}
	_, current := f.snapshot()
	if current != oldLabel {
		t.Fatalf("expected restored label %q, got %q", oldLabel, current)
	}
}

func TestSetProcessLabel_RestoreFailureAggregatesErrors(t *testing.T) {
	const (
		oldLabel = "system_u:system_r:spc_t:s0"
		newLabel = "system_u:object_r:container_t:s0:c1,c2"
	)
	setErr := fmt.Errorf("write attr/exec: %w", os.ErrPermission)
	restoreErr := errors.New("restore write failed")
	f := newFakeExecLabel(oldLabel)
	// Both the new label and the rollback to the old label fail.
	f.failNext[newLabel] = setErr
	f.failNext[oldLabel] = restoreErr
	withSeams(t, f)

	err := setProcessLabelTransaction(newLabel)
	if err == nil {
		t.Fatal("expected aggregated error, got nil")
	}
	// The aggregate must retain both the original denial and the restore error.
	if !errors.Is(err, ErrLabelTransitionDenied) {
		t.Fatalf("aggregate should include denial, got %v", err)
	}
	if !errors.Is(err, restoreErr) {
		t.Fatalf("aggregate should include restore error, got %v", err)
	}
}

func TestSetProcessLabel_ReadFailureLeavesStateUntouched(t *testing.T) {
	const newLabel = "system_u:object_r:container_t:s0:c1,c2"
	readErr := errors.New("cannot open attr/exec")
	f := newFakeExecLabel("")
	withSeams(t, f)
	readExecLabel = func() (string, error) { return "", readErr }

	err := setProcessLabelTransaction(newLabel)
	if !errors.Is(err, readErr) {
		t.Fatalf("expected read error, got %v", err)
	}
	writes, _ := f.snapshot()
	if len(writes) != 0 {
		t.Fatalf("no writes expected after read failure, got %v", writes)
	}
}

func TestSetProcessLabel_ConcurrentTransitionsAreSerialized(t *testing.T) {
	const base = "system_u:object_r:container_t:s0:c"
	f := newFakeExecLabel("")
	withSeams(t, f)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lbl := fmt.Sprintf("%s%d,c%d", base, i, i+1)
			if err := setProcessLabelTransaction(lbl); err != nil {
				t.Errorf("transition %d failed: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	// Every goroutine's label must have been written exactly once; the mutex
	// guarantees no interleaving that drops or corrupts a transition.
	writes, _ := f.snapshot()
	if len(writes) != 50 {
		t.Fatalf("expected 50 serialized writes, got %d", len(writes))
	}
	seen := make(map[string]int, len(writes))
	for _, w := range writes {
		seen[w]++
	}
	for i := 0; i < 50; i++ {
		lbl := fmt.Sprintf("%s%d,c%d", base, i, i+1)
		if seen[lbl] != 1 {
			t.Fatalf("label %q written %d times, want exactly once", lbl, seen[lbl])
		}
	}
}

// TestSetProcessLabel_RealAPIDisabled compiles against the public API on a
// host without SELinux and asserts the documented no-op behavior.
func TestSetProcessLabel_RealAPIDisabled(t *testing.T) {
	if selinux.GetEnabled() {
		t.Skip("SELinux enabled; no-op path not applicable on this host.")
	}
	if err := SetProcessLabel("system_u:object_r:container_t:s0:c1,c2"); err != nil {
		t.Fatalf("SetProcessLabel must be a no-op when disabled: %v", err)
	}
}
