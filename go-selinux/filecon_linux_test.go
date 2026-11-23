package selinux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setEnabledForTest forces the SELinux enabled state for the duration of a
// test, restoring the previous state afterwards.
func setEnabledForTest(t *testing.T, enabled bool) {
	t.Helper()
	state.Lock()
	savedSet, savedEnabled := state.enabledSet, state.enabled
	state.Unlock()
	state.setEnable(enabled)
	t.Cleanup(func() {
		state.Lock()
		state.enabledSet, state.enabled = savedSet, savedEnabled
		state.Unlock()
	})
}

// stubPolicyGeneration replaces the policy generation source for the
// duration of a test.
func stubPolicyGeneration(t *testing.T, gen func() uint64) {
	t.Helper()
	saved := policyGeneration
	policyGeneration = gen
	t.Cleanup(func() { policyGeneration = saved })
}

// stubMatchFileContext replaces the underlying file context matcher for the
// duration of a test.
func stubMatchFileContext(t *testing.T, match func(string) (string, error)) {
	t.Helper()
	saved := matchFileContext
	matchFileContext = match
	t.Cleanup(func() { matchFileContext = saved })
}

// resetFileConCacheForTest makes sure a test starts and ends with empty
// file context caches.
func resetFileConCacheForTest(t *testing.T) {
	t.Helper()
	flushFileContextCache()
	t.Cleanup(flushFileContextCache)
}

func TestFileContextCacheHit(t *testing.T) {
	setEnabledForTest(t, true)
	resetFileConCacheForTest(t)
	stubPolicyGeneration(t, func() uint64 { return 1 })

	var calls atomic.Int32
	stubMatchFileContext(t, func(fpath string) (string, error) {
		calls.Add(1)
		return "system_u:object_r:etc_t:s0", nil
	})

	for i := 0; i < 3; i++ {
		label, err := FileContextLabel("/etc/hosts")
		if err != nil {
			t.Fatalf("lookup %d: unexpected error: %v", i, err)
		}
		if want := "system_u:object_r:etc_t:s0"; label != want {
			t.Fatalf("lookup %d: got %q, want %q", i, label, want)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("underlying match executed %d times, want 1 (cached)", got)
	}
}

func TestFileContextCachePolicyReload(t *testing.T) {
	setEnabledForTest(t, true)
	resetFileConCacheForTest(t)

	var gen atomic.Uint64
	gen.Store(1)
	stubPolicyGeneration(t, gen.Load)

	var calls atomic.Int32
	stubMatchFileContext(t, func(fpath string) (string, error) {
		calls.Add(1)
		return fmt.Sprintf("system_u:object_r:etc_t:s0 /* gen %d */", gen.Load()), nil
	})

	label1, err := FileContextLabel("/etc/hosts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate a policy reload: the generation changes and the policy now
	// yields a different label for the same path.
	gen.Store(2)
	label2, err := FileContextLabel("/etc/hosts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label1 == label2 {
		t.Fatalf("label %q survived a policy reload; old generation entries must not hit", label1)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("underlying match executed %d times, want 2 (one per generation)", got)
	}

	// Entries from an older generation must not be served even if the
	// generation number is reused.
	gen.Store(1)
	if _, err := FileContextLabel("/etc/hosts"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("underlying match executed %d times, want 3 (old generation entries dropped)", got)
	}
}

func TestFileContextCacheConcurrent(t *testing.T) {
	setEnabledForTest(t, true)
	resetFileConCacheForTest(t)
	stubPolicyGeneration(t, func() uint64 { return 1 })

	var calls atomic.Int32
	stubMatchFileContext(t, func(fpath string) (string, error) {
		calls.Add(1)
		// Slow the matcher down to make concurrent lookups overlap.
		time.Sleep(10 * time.Millisecond)
		return "system_u:object_r:etc_t:s0", nil
	})

	const goroutines = 32
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	labels := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			labels[i], errs[i] = FileContextLabel("/etc/hosts")
		}()
	}
	wg.Wait()

	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, errs[i])
		}
		if want := "system_u:object_r:etc_t:s0"; labels[i] != want {
			t.Fatalf("goroutine %d: got %q, want %q", i, labels[i], want)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("underlying match executed %d times, want 1 (singleflight within one generation)", got)
	}
}

func TestFileContextCacheUnknownPath(t *testing.T) {
	setEnabledForTest(t, true)
	resetFileConCacheForTest(t)
	stubPolicyGeneration(t, func() uint64 { return 1 })

	var calls atomic.Int32
	known := false
	stubMatchFileContext(t, func(fpath string) (string, error) {
		calls.Add(1)
		if !known {
			return "", ErrContextMissing
		}
		return "system_u:object_r:etc_t:s0", nil
	})

	for i := 0; i < 2; i++ {
		_, err := FileContextLabel("/no/such/path")
		if !errors.Is(err, ErrContextMissing) {
			t.Fatalf("lookup %d: got error %v, want ErrContextMissing", i, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("underlying match executed %d times, want 2 (unknown paths must not be cached)", got)
	}

	// A path that was unknown before must not become a permanent failure:
	// once the policy can label it, the lookup must succeed.
	known = true
	label, err := FileContextLabel("/no/such/path")
	if err != nil {
		t.Fatalf("unexpected error after path became known: %v", err)
	}
	if want := "system_u:object_r:etc_t:s0"; label != want {
		t.Fatalf("got %q, want %q", label, want)
	}
}

func TestFileContextCachePolicyError(t *testing.T) {
	setEnabledForTest(t, true)
	resetFileConCacheForTest(t)
	stubPolicyGeneration(t, func() uint64 { return 1 })

	errPolicy := errors.New("policy unavailable")
	var calls atomic.Int32
	broken := true
	stubMatchFileContext(t, func(fpath string) (string, error) {
		calls.Add(1)
		if broken {
			return "", errPolicy
		}
		return "system_u:object_r:etc_t:s0", nil
	})

	for i := 0; i < 2; i++ {
		_, err := FileContextLabel("/etc/hosts")
		if !errors.Is(err, errPolicy) {
			t.Fatalf("lookup %d: got error %v, want %v", i, err, errPolicy)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("underlying match executed %d times, want 2 (policy errors must not be cached)", got)
	}

	// A policy error must not be cached as a permanent success: once the
	// underlying problem is gone, lookups must succeed again.
	broken = false
	label, err := FileContextLabel("/etc/hosts")
	if err != nil {
		t.Fatalf("unexpected error after policy recovered: %v", err)
	}
	if want := "system_u:object_r:etc_t:s0"; label != want {
		t.Fatalf("got %q, want %q", label, want)
	}
}

func TestFileContextCacheFlush(t *testing.T) {
	setEnabledForTest(t, true)
	resetFileConCacheForTest(t)
	stubPolicyGeneration(t, func() uint64 { return 1 })

	var calls atomic.Int32
	stubMatchFileContext(t, func(fpath string) (string, error) {
		calls.Add(1)
		return "system_u:object_r:etc_t:s0", nil
	})

	if _, err := FileContextLabel("/etc/hosts"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("underlying match executed %d times, want 1", got)
	}

	FlushFileContextCache()

	label, err := FileContextLabel("/etc/hosts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "system_u:object_r:etc_t:s0"; label != want {
		t.Fatalf("got %q, want %q", label, want)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("underlying match executed %d times, want 2 (flush must clear the local cache)", got)
	}
}

func TestFileContextCacheDisabled(t *testing.T) {
	setEnabledForTest(t, false)
	resetFileConCacheForTest(t)

	var calls atomic.Int32
	stubMatchFileContext(t, func(fpath string) (string, error) {
		calls.Add(1)
		return "system_u:object_r:etc_t:s0", nil
	})

	// With SELinux disabled the cache is bypassed entirely, preserving the
	// behavior of a plain uncached lookup.
	for i := 0; i < 2; i++ {
		label, err := FileContextLabel("/etc/hosts")
		if err != nil {
			t.Fatalf("lookup %d: unexpected error: %v", i, err)
		}
		if want := "system_u:object_r:etc_t:s0"; label != want {
			t.Fatalf("lookup %d: got %q, want %q", i, label, want)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("underlying match executed %d times, want 2 (cache bypassed while disabled)", got)
	}
}

func TestFileContextEmptyPath(t *testing.T) {
	if _, err := FileContextLabel(""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("got error %v, want ErrEmptyPath", err)
	}
}

func TestFileContextSpecsMatch(t *testing.T) {
	resetFileConCacheForTest(t)

	dir := t.TempDir()
	fc := filepath.Join(dir, "file_contexts")
	contents := `# a comment, followed by a blank line

/var/log(/.*)?	system_u:object_r:var_log_t:s0
/var/log/httpd(/.*)?	-d	system_u:object_r:httpd_log_t:s0
/etc/passwd	--	system_u:object_r:passwd_file_t:s0
/dev/pts(/.*)?	<<none>>
/badregex[	system_u:object_r:bad_t:s0
malformed
`
	if err := os.WriteFile(fc, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := fileContextsFile
	fileContextsFile = func() string { return fc }
	t.Cleanup(func() { fileContextsFile = saved })

	var gen atomic.Uint64
	gen.Store(1)
	stubPolicyGeneration(t, gen.Load)

	tests := []struct {
		path string
		want string
	}{
		// The most specific (longest stem) entry wins.
		{"/var/log/httpd/error.log", "system_u:object_r:httpd_log_t:s0"},
		{"/var/log/messages", "system_u:object_r:var_log_t:s0"},
		// Entries with a file type column still match.
		{"/etc/passwd", "system_u:object_r:passwd_file_t:s0"},
	}
	for _, tc := range tests {
		label, err := matchFileContext(tc.path)
		if err != nil {
			t.Errorf("match %q: unexpected error: %v", tc.path, err)
			continue
		}
		if label != tc.want {
			t.Errorf("match %q: got %q, want %q", tc.path, label, tc.want)
		}
	}

	noMatch := []string{
		// No entry covers this path.
		"/nonexistent/path",
		// Patterns must match the whole path.
		"/etc/passwd.d",
		// "<<none>>" entries do not yield a context.
		"/dev/pts/0",
	}
	for _, path := range noMatch {
		if _, err := matchFileContext(path); !errors.Is(err, ErrContextMissing) {
			t.Errorf("match %q: got error %v, want ErrContextMissing", path, err)
		}
	}

	// A policy reload (generation change) must reload the specs from disk.
	contents += "/etc/motd	system_u:object_r:etc_t:s0\n"
	if err := os.WriteFile(fc, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	gen.Store(2)
	label, err := matchFileContext("/etc/motd")
	if err != nil {
		t.Fatalf("match after reload: unexpected error: %v", err)
	}
	if want := "system_u:object_r:etc_t:s0"; label != want {
		t.Fatalf("match after reload: got %q, want %q", label, want)
	}
}

func TestFileContextSpecsLoadError(t *testing.T) {
	resetFileConCacheForTest(t)
	stubPolicyGeneration(t, func() uint64 { return 1 })

	dir := t.TempDir()
	fc := filepath.Join(dir, "file_contexts")
	saved := fileContextsFile
	fileContextsFile = func() string { return fc }
	t.Cleanup(func() { fileContextsFile = saved })

	// The file_contexts file does not exist: a distinct policy error must
	// be returned (not ErrContextMissing), and it must not be cached.
	for i := 0; i < 2; i++ {
		_, err := matchFileContext("/etc/hosts")
		if err == nil {
			t.Fatalf("lookup %d: expected an error, got nil", i)
		}
		if errors.Is(err, ErrContextMissing) {
			t.Fatalf("lookup %d: got ErrContextMissing, want a policy load error", i)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("lookup %d: got error %v, want os.ErrNotExist", i, err)
		}
	}

	// Once the file appears, the lookup must succeed: the load error was
	// not cached as a permanent failure.
	if err := os.WriteFile(fc, []byte("/etc/hosts	system_u:object_r:etc_t:s0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	label, err := matchFileContext("/etc/hosts")
	if err != nil {
		t.Fatalf("unexpected error after file_contexts appeared: %v", err)
	}
	if want := "system_u:object_r:etc_t:s0"; label != want {
		t.Fatalf("got %q, want %q", label, want)
	}
}

func TestPatternStem(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{"/etc/passwd", "/etc/passwd"},
		{"/var/log(/.*)?", "/var/log"},
		{`/var/[^/]+/log`, "/var/"},
		{`\.pid$`, ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := patternStem(tc.pattern); got != tc.want {
			t.Errorf("patternStem(%q): got %q, want %q", tc.pattern, got, tc.want)
		}
	}
}
