package selinux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// stubFileContexts points the policy loader at files for the duration of a
// test and clears the compiled rule cache afterwards.
func stubFileContexts(t *testing.T, files ...string) {
	t.Helper()
	savedFiles := fileContextsFiles
	fileContextsFiles = func() []string { return files }
	flushFileContextCache()
	t.Cleanup(func() {
		fileContextsFiles = savedFiles
		flushFileContextCache()
	})
}

// stubFileContextsEnabled overrides the SELinux enabled check so that apply
// paths can be exercised on hosts without SELinux.
func stubFileContextsEnabled(t *testing.T, enabled bool) {
	t.Helper()
	saved := fileContextsEnabled
	fileContextsEnabled = func() bool { return enabled }
	t.Cleanup(func() { fileContextsEnabled = saved })
}

// fakeLabelStore emulates the security.selinux xattr without requiring
// SELinux privileges. Paths that do not exist on disk report fs.ErrNotExist,
// just like the real getxattr.
type fakeLabelStore struct { //nolint:govet // field alignment is irrelevant for a test helper
	labels  map[string]string
	writes  []string
	readErr error
	mu      sync.Mutex
}

func newFakeLabelStore(t *testing.T) *fakeLabelStore {
	t.Helper()
	store := &fakeLabelStore{labels: make(map[string]string)}
	savedRead := readFileContextXattr
	savedWrite := writeFileContextXattr
	readFileContextXattr = func(path string, _ bool) (string, error) {
		store.mu.Lock()
		defer store.mu.Unlock()
		if store.readErr != nil {
			return "", store.readErr
		}
		if _, err := os.Lstat(path); err != nil {
			return "", &os.PathError{Op: "lgetxattr", Path: path, Err: err}
		}
		label, ok := store.labels[path]
		if !ok {
			return "", &os.PathError{Op: "lgetxattr", Path: path, Err: unix.ENODATA}
		}
		return label, nil
	}
	writeFileContextXattr = func(path, context string, _ bool) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.labels[path] = context
		store.writes = append(store.writes, path)
		return nil
	}
	t.Cleanup(func() {
		readFileContextXattr = savedRead
		writeFileContextXattr = savedWrite
	})
	return store
}

func (s *fakeLabelStore) get(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.labels[path]
}

func (s *fakeLabelStore) set(path, label string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labels[path] = label
}

func (s *fakeLabelStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

// writePolicyFile writes a file_contexts file and returns its path.
func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file_contexts")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newRootfs creates a rootfs directory with a few entries and returns it.
func newRootfs(t *testing.T) string {
	t.Helper()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), []byte("root:x:0:0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "sub", "config"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An absolute symlink, as commonly found in container rootfs trees. It
	// must be resolved inside the rootfs, not on the host.
	if err := os.Symlink("/etc/passwd", filepath.Join(rootfs, "etc", "passwd-link")); err != nil {
		t.Fatal(err)
	}
	// A relative symlink.
	if err := os.Symlink("passwd", filepath.Join(rootfs, "etc", "relative-link")); err != nil {
		t.Fatal(err)
	}
	return rootfs
}

func TestPatternLiteralPrefix(t *testing.T) {
	tests := []struct {
		pattern string
		prefix  string
		hasMeta bool
	}{
		{"/etc/passwd", "/etc/passwd", false},
		{"/etc/.*", "/etc/", true},
		{"/etc/(passwd|shadow)", "/etc/", true},
		{`/etc/foo\.txt`, "/etc/foo.txt", false},
		{`/a\+b/c`, "/a+b/c", false},
		{`/a\/b`, "/a/b", false},
		{"/a[bc]d", "/a", true},
		{`/trailing\`, "/trailing", true},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			prefix, hasMeta := patternLiteralPrefix(tc.pattern)
			if prefix != tc.prefix || hasMeta != tc.hasMeta {
				t.Errorf("patternLiteralPrefix(%q) = (%q, %v), want (%q, %v)",
					tc.pattern, prefix, hasMeta, tc.prefix, tc.hasMeta)
			}
		})
	}
}

func TestParseFileContextRules(t *testing.T) {
	path := writePolicyFile(t, `# comment
/plain system_u:object_r:a_t:s0
/etc/.*  system_u:object_r:b_t:s0
/etc/dir    -d   system_u:object_r:c_t:s0
/etc/link   -l   system_u:object_r:d_t:s0
/bad/type   -x   system_u:object_r:e_t:s0
/not-enough
/bad/(regex  system_u:object_r:f_t:s0
/with/extras system_u:object_r:g_t:s0 extra
/none <<none>>
`)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var rules []fileContextRule
	if err := parseFileContextRules(f, &rules); err != nil {
		t.Fatal(err)
	}

	want := []struct {
		pattern string
		context string
		kind    byte
	}{
		{"/plain", "system_u:object_r:a_t:s0", 0},
		{"/etc/.*", "system_u:object_r:b_t:s0", 0},
		{"/etc/dir", "system_u:object_r:c_t:s0", 'd'},
		{"/etc/link", "system_u:object_r:d_t:s0", 'l'},
		{"/with/extras", "system_u:object_r:g_t:s0", 0},
		{"/none", "<<none>>", 0},
	}
	if len(rules) != len(want) {
		t.Fatalf("parsed %d rules, want %d: %+v", len(rules), len(want), rules)
	}
	for i, w := range want {
		if rules[i].pattern != w.pattern || rules[i].kind != w.kind || rules[i].context != w.context {
			t.Errorf("rule %d = (%q, %q, %q), want (%q, %q, %q)",
				i, rules[i].pattern, rules[i].kind, rules[i].context, w.pattern, w.kind, w.context)
		}
	}
}

func TestFileContextRulePriority(t *testing.T) {
	// The same path matches all four rules. The literal rule with the
	// longest prefix must win over the shorter literal and both regex rules.
	base := writePolicyFile(t, `/etc/.* system_u:object_r:regex_t:s0
/etc/pass.* system_u:object_r:long-regex_t:s0
/etc/passwd system_u:object_r:literal_t:s0
`)
	stubFileContexts(t, base)

	rule, err := matchFileContextRule("/etc/passwd", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil {
		t.Fatal("no rule matched /etc/passwd")
	}
	if got, want := rule.context, "system_u:object_r:literal_t:s0"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// /etc/passwd2 does not match the literal rule, so the longest matching
	// regex wins.
	rule, err = matchFileContextRule("/etc/passwd2", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil {
		t.Fatal("no rule matched /etc/passwd2")
	}
	if got, want := rule.context, "system_u:object_r:long-regex_t:s0"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFileContextRulePriorityLaterWins(t *testing.T) {
	// Equal-specificity rules: the later definition wins, as in libselinux.
	base := writePolicyFile(t, `/etc/pass.* system_u:object_r:first_t:s0
/etc/pass.* system_u:object_r:second_t:s0
`)
	stubFileContexts(t, base)

	rule, err := matchFileContextRule("/etc/passwd", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil {
		t.Fatal("no rule matched")
	}
	if got, want := rule.context, "system_u:object_r:second_t:s0"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFileContextRulePriorityOverrideFile(t *testing.T) {
	// A later policy file (for example file_contexts.local) overrides an
	// entry from the base file.
	base := writePolicyFile(t, "/etc/passwd system_u:object_r:base_t:s0\n")
	local := base + ".local"
	if err := os.WriteFile(local, []byte("/etc/passwd system_u:object_r:local_t:s0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubFileContexts(t, base, local)

	rule, err := matchFileContextRule("/etc/passwd", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil {
		t.Fatal("no rule matched")
	}
	if got, want := rule.context, "system_u:object_r:local_t:s0"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFileContextRuleKindFiltering(t *testing.T) {
	base := writePolicyFile(t, `/etc/special -d system_u:object_r:dir_t:s0
/etc/special -l system_u:object_r:link_t:s0
`)
	stubFileContexts(t, base)

	for _, tc := range []struct {
		want string
		kind byte
	}{
		{"system_u:object_r:dir_t:s0", 'd'},
		{"system_u:object_r:link_t:s0", 'l'},
	} {
		rule, err := matchFileContextRule("/etc/special", tc.kind)
		if err != nil {
			t.Fatal(err)
		}
		if rule == nil || rule.context != tc.want {
			t.Errorf("kind %q: got %+v, want context %q", tc.kind, rule, tc.want)
		}
	}
}

func TestLookupFileContextRelativeRootfs(t *testing.T) {
	rootfs := newRootfs(t)
	policy := writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0
/etc/passwd-link system_u:object_r:link_t:s0
`)
	stubFileContexts(t, policy)

	for _, fpath := range []string{"etc/passwd", "/etc/passwd"} {
		res, err := LookupFileContext(fpath, &FileContextOptions{Rootfs: rootfs})
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", fpath, err)
		}
		if res.Path != fpath {
			t.Errorf("%q: Path = %q, want the original path", fpath, res.Path)
		}
		if res.Rootfs != rootfs {
			t.Errorf("%q: Rootfs = %q, want %q", fpath, res.Rootfs, rootfs)
		}
		// The host path is the rootfs path; the policy path is the path as
		// seen inside the rootfs.
		if want := filepath.Join(rootfs, "etc", "passwd"); res.ResolvedPath != want {
			t.Errorf("%q: ResolvedPath = %q, want %q", fpath, res.ResolvedPath, want)
		}
		if res.PolicyPath != "/etc/passwd" {
			t.Errorf("%q: PolicyPath = %q, want /etc/passwd", fpath, res.PolicyPath)
		}
		if got, want := res.Context, "system_u:object_r:passwd_t:s0"; got != want {
			t.Errorf("%q: Context = %q, want %q", fpath, got, want)
		}
		if res.Rule != "/etc/passwd" {
			t.Errorf("%q: Rule = %q, want /etc/passwd", fpath, res.Rule)
		}
		if written := newFakeLabelStore(t).writeCount(); written != 0 {
			t.Errorf("LookupFileContext wrote %d labels, want 0", written)
		}
	}
}

func TestLookupFileContextRelativeWithoutRootfs(t *testing.T) {
	stubFileContexts(t, writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0`))

	for _, opts := range []*FileContextOptions{nil, {}} {
		_, err := LookupFileContext("etc/passwd", opts)
		if !errors.Is(err, ErrRelativePathWithoutRootfs) {
			t.Errorf("opts %+v: got error %v, want ErrRelativePathWithoutRootfs", opts, err)
		}
	}
}

func TestLookupFileContextInvalidRootfs(t *testing.T) {
	stubFileContexts(t, writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0`))

	_, err := LookupFileContext("/etc/passwd", &FileContextOptions{Rootfs: "relative/rootfs"})
	if !errors.Is(err, ErrInvalidRootfs) {
		t.Errorf("got error %v, want ErrInvalidRootfs", err)
	}
}

func TestLookupFileContextIntermediateSymlink(t *testing.T) {
	rootfs := newRootfs(t)
	policy := writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0
/dir-link/passwd system_u:object_r:linkdir_t:s0
`)
	stubFileContexts(t, policy)

	// Not following the final component: intermediate directory symlinks are
	// still resolved before the policy sees the path, so the rule that
	// matches the real path wins over the rule that names the link.
	if err := os.Symlink("etc", filepath.Join(rootfs, "dir-link")); err != nil {
		t.Fatal(err)
	}
	res, err := LookupFileContext("dir-link/passwd", &FileContextOptions{Rootfs: rootfs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := res.PolicyPath, "/etc/passwd"; got != want {
		t.Errorf("PolicyPath = %q, want %q", got, want)
	}
	if got, want := res.Context, "system_u:object_r:passwd_t:s0"; got != want {
		t.Errorf("Context = %q, want %q", got, want)
	}
	if got, want := res.ResolvedPath, filepath.Join(rootfs, "etc", "passwd"); got != want {
		t.Errorf("ResolvedPath = %q, want %q", got, want)
	}
}

func TestLookupFileContextAbsolutePathCompat(t *testing.T) {
	// Without a rootfs, an absolute path keeps the historical behavior: the
	// host path itself is matched against the policy.
	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := writePolicyFile(t, fmt.Sprintf(`%s system_u:object_r:host_t:s0
`, target))
	stubFileContexts(t, policy)

	res, err := LookupFileContext(target, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ResolvedPath != target || res.PolicyPath != target {
		t.Errorf("ResolvedPath/PolicyPath = %q/%q, want %q/%q",
			res.ResolvedPath, res.PolicyPath, target, target)
	}
	if res.Rootfs != "" {
		t.Errorf("Rootfs = %q, want empty", res.Rootfs)
	}
	if got, want := res.Context, "system_u:object_r:host_t:s0"; got != want {
		t.Errorf("Context = %q, want %q", got, want)
	}
}

func TestFollowSymlinksOption(t *testing.T) {
	rootfs := newRootfs(t)
	policy := writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0
/etc/passwd-link -l system_u:object_r:link_t:s0
/etc/relative-link -l system_u:object_r:relative_t:s0
`)
	stubFileContexts(t, policy)

	t.Run("not followed", func(t *testing.T) {
		res, err := LookupFileContext("etc/passwd-link", &FileContextOptions{Rootfs: rootfs})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.FollowSymlinks {
			t.Error("FollowSymlinks = true, want false")
		}
		// The link itself is resolved and matched; it is not replaced by its
		// target.
		if want := filepath.Join(rootfs, "etc", "passwd-link"); res.ResolvedPath != want {
			t.Errorf("ResolvedPath = %q, want %q", res.ResolvedPath, want)
		}
		if got, want := res.PolicyPath, "/etc/passwd-link"; got != want {
			t.Errorf("PolicyPath = %q, want %q", got, want)
		}
		if got, want := res.Context, "system_u:object_r:link_t:s0"; got != want {
			t.Errorf("Context = %q, want %q", got, want)
		}
	})

	t.Run("followed", func(t *testing.T) {
		res, err := LookupFileContext("etc/passwd-link", &FileContextOptions{Rootfs: rootfs, FollowSymlinks: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.FollowSymlinks {
			t.Error("FollowSymlinks = false, want true")
		}
		if want := filepath.Join(rootfs, "etc", "passwd"); res.ResolvedPath != want {
			t.Errorf("ResolvedPath = %q, want %q", res.ResolvedPath, want)
		}
		// The policy sees the target path, not the link path.
		if got, want := res.PolicyPath, "/etc/passwd"; got != want {
			t.Errorf("PolicyPath = %q, want %q", got, want)
		}
		if got, want := res.Context, "system_u:object_r:passwd_t:s0"; got != want {
			t.Errorf("Context = %q, want %q", got, want)
		}
		// The original path remains available for diagnostics.
		if res.Path != "etc/passwd-link" {
			t.Errorf("Path = %q, want the original path", res.Path)
		}
	})

	t.Run("relative symlink followed", func(t *testing.T) {
		res, err := LookupFileContext("etc/relative-link", &FileContextOptions{Rootfs: rootfs, FollowSymlinks: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, want := res.PolicyPath, "/etc/passwd"; got != want {
			t.Errorf("PolicyPath = %q, want %q", got, want)
		}
	})

	t.Run("absolute symlink stays inside rootfs", func(t *testing.T) {
		// The link target is /etc/passwd; it must resolve to
		// <rootfs>/etc/passwd and not to the host's /etc/passwd.
		res, err := LookupFileContext("/etc/passwd-link", &FileContextOptions{Rootfs: rootfs, FollowSymlinks: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(rootfs, "etc", "passwd")
		if res.ResolvedPath != want {
			t.Errorf("ResolvedPath = %q, want %q", res.ResolvedPath, want)
		}
	})
}

func TestMissingFile(t *testing.T) {
	rootfs := t.TempDir()
	policy := writePolicyFile(t, `/etc/missing system_u:object_r:missing_t:s0
/etc/.* system_u:object_r:fallback_t:s0
`)
	stubFileContexts(t, policy)

	// A file that does not exist yet must still match the policy, and its
	// resolution must be reported.
	res, err := LookupFileContext("etc/missing", &FileContextOptions{Rootfs: rootfs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := filepath.Join(rootfs, "etc", "missing"); res.ResolvedPath != want {
		t.Errorf("ResolvedPath = %q, want %q", res.ResolvedPath, want)
	}
	if got, want := res.Context, "system_u:object_r:missing_t:s0"; got != want {
		t.Errorf("Context = %q, want %q", got, want)
	}
	if !res.Missing {
		t.Error("Missing = false, want true for a path that does not exist")
	}
}

func TestMissingFileApply(t *testing.T) {
	rootfs := t.TempDir()
	policy := writePolicyFile(t, `/etc/missing system_u:object_r:missing_t:s0
`)
	stubFileContexts(t, policy)
	stubFileContextsEnabled(t, true)
	store := newFakeLabelStore(t)

	// Applying to a path that does not exist must not fail and must not
	// write a label.
	res, err := ApplyFileContext("etc/missing", &FileContextOptions{Rootfs: rootfs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applied {
		t.Error("Applied = true for a missing file, want false")
	}
	if got := store.writeCount(); got != 0 {
		t.Errorf("wrote %d labels for a missing file, want 0", got)
	}
}

func TestContextMissingReportsResolution(t *testing.T) {
	rootfs := newRootfs(t)
	policy := writePolicyFile(t, `/usr/bin/.* system_u:object_r:bin_t:s0
`)
	stubFileContexts(t, policy)

	res, err := LookupFileContext("etc/passwd", &FileContextOptions{Rootfs: rootfs})
	if !errors.Is(err, ErrContextMissing) {
		t.Fatalf("got error %v, want ErrContextMissing", err)
	}
	if res == nil {
		t.Fatal("expected a result with resolution details, got nil")
	}
	if want := filepath.Join(rootfs, "etc", "passwd"); res.ResolvedPath != want {
		t.Errorf("ResolvedPath = %q, want %q", res.ResolvedPath, want)
	}
	if got, want := res.PolicyPath, "/etc/passwd"; got != want {
		t.Errorf("PolicyPath = %q, want %q", got, want)
	}
	if res.Path != "etc/passwd" {
		t.Errorf("Path = %q, want the original path", res.Path)
	}
}

func TestSetFileContext(t *testing.T) {
	rootfs := newRootfs(t)
	target := filepath.Join(rootfs, "etc", "passwd")
	stubFileContextsEnabled(t, true)

	t.Run("sets a label", func(t *testing.T) {
		store := newFakeLabelStore(t)
		res, err := SetFileContext("etc/passwd", "system_u:object_r:passwd_t:s0", &FileContextOptions{Rootfs: rootfs})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Applied {
			t.Error("Applied = false, want true")
		}
		if got, want := store.get(target), "system_u:object_r:passwd_t:s0"; got != want {
			t.Errorf("label = %q, want %q", got, want)
		}
	})

	t.Run("empty context keeps the existing label", func(t *testing.T) {
		store := newFakeLabelStore(t)
		store.set(target, "system_u:object_r:existing_t:s0")
		res, err := SetFileContext("etc/passwd", "", &FileContextOptions{Rootfs: rootfs})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Applied {
			t.Error("Applied = true, want false")
		}
		if got, want := store.get(target), "system_u:object_r:existing_t:s0"; got != want {
			t.Errorf("label = %q, want the existing label %q", got, want)
		}
		if res.ExistingContext != "system_u:object_r:existing_t:s0" {
			t.Errorf("ExistingContext = %q, want the existing label", res.ExistingContext)
		}
		if got := store.writeCount(); got != 0 {
			t.Errorf("wrote %d labels, want 0", got)
		}
	})

	t.Run("<<none>> keeps the existing label", func(t *testing.T) {
		store := newFakeLabelStore(t)
		store.set(target, "system_u:object_r:existing_t:s0")
		res, err := SetFileContext("etc/passwd", "<<none>>", &FileContextOptions{Rootfs: rootfs})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Applied || res.Context != "" {
			t.Errorf("Applied = %v, Context = %q; want no change and empty context", res.Applied, res.Context)
		}
		if got := store.get(target); got != "system_u:object_r:existing_t:s0" {
			t.Errorf("label = %q, want the existing label", got)
		}
	})

	t.Run("existing label is never replaced silently", func(t *testing.T) {
		store := newFakeLabelStore(t)
		store.set(target, "system_u:object_r:existing_t:s0")
		res, err := SetFileContext("etc/passwd", "system_u:object_r:new_t:s0", &FileContextOptions{Rootfs: rootfs})
		if !errors.Is(err, ErrFileContextConflict) {
			t.Fatalf("got error %v, want ErrFileContextConflict", err)
		}
		var conflictErr *FileContextConflictError
		if !errors.As(err, &conflictErr) {
			t.Fatalf("error %v is not a *FileContextConflictError", err)
		}
		if conflictErr.Existing != "system_u:object_r:existing_t:s0" ||
			conflictErr.Context != "system_u:object_r:new_t:s0" {
			t.Errorf("conflict error = %+v, want existing and requested labels", conflictErr)
		}
		if res.ResolvedPath != target {
			t.Errorf("ResolvedPath = %q, want %q", res.ResolvedPath, target)
		}
		if got := store.get(target); got != "system_u:object_r:existing_t:s0" {
			t.Errorf("label = %q, want the existing label", got)
		}
		if got := store.writeCount(); got != 0 {
			t.Errorf("wrote %d labels, want 0", got)
		}
	})

	t.Run("explicit overwrite", func(t *testing.T) {
		store := newFakeLabelStore(t)
		store.set(target, "system_u:object_r:existing_t:s0")
		res, err := SetFileContext("etc/passwd", "system_u:object_r:new_t:s0", &FileContextOptions{
			Rootfs:   rootfs,
			Conflict: FileContextConflictOverwrite,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Applied {
			t.Error("Applied = false, want true")
		}
		if got, want := store.get(target), "system_u:object_r:new_t:s0"; got != want {
			t.Errorf("label = %q, want %q", got, want)
		}
		if res.ExistingContext != "system_u:object_r:existing_t:s0" {
			t.Errorf("ExistingContext = %q, want the previous label", res.ExistingContext)
		}
	})

	t.Run("explicit keep", func(t *testing.T) {
		store := newFakeLabelStore(t)
		store.set(target, "system_u:object_r:existing_t:s0")
		res, err := SetFileContext("etc/passwd", "system_u:object_r:new_t:s0", &FileContextOptions{
			Rootfs:   rootfs,
			Conflict: FileContextConflictKeep,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Applied {
			t.Error("Applied = true, want false")
		}
		if res.ExistingContext != "system_u:object_r:existing_t:s0" {
			t.Errorf("ExistingContext = %q, want the existing label", res.ExistingContext)
		}
		if got := store.get(target); got != "system_u:object_r:existing_t:s0" {
			t.Errorf("label = %q, want the existing label", got)
		}
	})

	t.Run("same label is not rewritten", func(t *testing.T) {
		store := newFakeLabelStore(t)
		store.set(target, "system_u:object_r:passwd_t:s0")
		res, err := SetFileContext("etc/passwd", "system_u:object_r:passwd_t:s0", &FileContextOptions{Rootfs: rootfs})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Applied {
			t.Error("Applied = true, want false")
		}
		if got := store.writeCount(); got != 0 {
			t.Errorf("wrote %d labels, want 0", got)
		}
	})
}

func TestApplyFileContext(t *testing.T) {
	rootfs := newRootfs(t)
	target := filepath.Join(rootfs, "etc", "passwd")
	policy := writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0
`)
	stubFileContexts(t, policy)
	stubFileContextsEnabled(t, true)

	store := newFakeLabelStore(t)
	res, err := ApplyFileContext("etc/passwd", &FileContextOptions{Rootfs: rootfs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Applied {
		t.Error("Applied = false, want true")
	}
	if got, want := store.get(target), "system_u:object_r:passwd_t:s0"; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
	if res.Rule != "/etc/passwd" || res.PolicyPath != "/etc/passwd" {
		t.Errorf("Rule/PolicyPath = %q/%q, want /etc/passwd", res.Rule, res.PolicyPath)
	}

	// A second application with the same policy must not rewrite the label.
	writes := store.writeCount()
	if _, err := ApplyFileContext("etc/passwd", &FileContextOptions{Rootfs: rootfs}); err != nil {
		t.Fatalf("second apply: unexpected error: %v", err)
	}
	if got := store.writeCount(); got != writes {
		t.Errorf("second apply wrote %d labels, want no writes", got-writes)
	}
}

func TestApplyFileContextConflict(t *testing.T) {
	rootfs := newRootfs(t)
	target := filepath.Join(rootfs, "etc", "passwd")
	policy := writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0
`)
	stubFileContexts(t, policy)
	stubFileContextsEnabled(t, true)

	store := newFakeLabelStore(t)
	store.set(target, "system_u:object_r:existing_t:s0")

	if _, err := ApplyFileContext("etc/passwd", &FileContextOptions{Rootfs: rootfs}); !errors.Is(err, ErrFileContextConflict) {
		t.Fatalf("got error %v, want ErrFileContextConflict", err)
	}
	if got := store.get(target); got != "system_u:object_r:existing_t:s0" {
		t.Errorf("label = %q, want the existing label", got)
	}

	if _, err := ApplyFileContext("etc/passwd", &FileContextOptions{
		Rootfs:   rootfs,
		Conflict: FileContextConflictOverwrite,
	}); err != nil {
		t.Fatalf("overwrite: unexpected error: %v", err)
	}
	if got, want := store.get(target), "system_u:object_r:passwd_t:s0"; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
}

func TestApplyFileContextNoneRuleKeepsLabel(t *testing.T) {
	rootfs := newRootfs(t)
	target := filepath.Join(rootfs, "etc", "passwd")
	// The policy explicitly says "do not label this path".
	policy := writePolicyFile(t, `/etc/passwd <<none>>
`)
	stubFileContexts(t, policy)
	stubFileContextsEnabled(t, true)

	store := newFakeLabelStore(t)
	store.set(target, "system_u:object_r:existing_t:s0")

	res, err := ApplyFileContext("etc/passwd", &FileContextOptions{Rootfs: rootfs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Context != "" {
		t.Errorf("Context = %q, want empty for a <<none>> rule", res.Context)
	}
	if res.Applied {
		t.Error("Applied = true, want false")
	}
	if got := store.get(target); got != "system_u:object_r:existing_t:s0" {
		t.Errorf("label = %q, want the existing label", got)
	}
}

func TestFileContextDisabledHost(t *testing.T) {
	rootfs := newRootfs(t)
	policy := writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0
`)
	stubFileContexts(t, policy)
	stubFileContextsEnabled(t, false)
	store := newFakeLabelStore(t)

	res, err := ApplyFileContext("etc/passwd", &FileContextOptions{Rootfs: rootfs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applied {
		t.Error("Applied = true, want false when SELinux is disabled")
	}
	if res.Context != "system_u:object_r:passwd_t:s0" {
		t.Errorf("Context = %q, want the policy label", res.Context)
	}
	if got := store.writeCount(); got != 0 {
		t.Errorf("wrote %d labels, want 0", got)
	}
}

func TestFileContextImmediateCompatibility(t *testing.T) {
	// Absolute paths without a rootfs and without symlink following must
	// resolve exactly as before: the host path is used unchanged.
	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := writePolicyFile(t, fmt.Sprintf("%s$ system_u:object_r:host_t:s0\n", target))
	stubFileContexts(t, policy)

	res, err := LookupFileContext(target, &FileContextOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ResolvedPath != target {
		t.Errorf("ResolvedPath = %q, want %q", res.ResolvedPath, target)
	}
}

func TestFileContextCacheInvalidation(t *testing.T) {
	base := writePolicyFile(t, "/etc/passwd system_u:object_r:first_t:s0\n")
	stubFileContexts(t, base)

	rule, err := matchFileContextRule("/etc/passwd", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil || rule.context != "system_u:object_r:first_t:s0" {
		t.Fatalf("first load: got %+v", rule)
	}

	// Rewriting the policy file changes its size and modification time, so
	// the cached rules must be reloaded without an explicit flush.
	if err := os.WriteFile(base, []byte("/etc/passwd system_u:object_r:second_t:s0\n/etc/other system_u:object_r:x_t:s0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rule, err = matchFileContextRule("/etc/passwd", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil || rule.context != "system_u:object_r:second_t:s0" {
		t.Fatalf("after rewrite: got %+v, want second_t", rule)
	}
}

func TestFlushFileContextCache(t *testing.T) {
	base := writePolicyFile(t, "/etc/passwd system_u:object_r:first_t:s0\n")
	stubFileContexts(t, base)

	// Warm the cache, then remove the policy file: a lookup after an explicit
	// flush must report the missing policy instead of serving stale rules.
	if _, err := matchFileContextRule("/etc/passwd", 0); err != nil {
		t.Fatal(err)
	}
	FlushFileContextCache()
	if _, err := matchFileContextRule("/etc/passwd", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	FlushFileContextCache()
	if _, err := matchFileContextRule("/etc/passwd", 0); err == nil {
		t.Error("expected an error after the policy file was removed and the cache flushed")
	}
}

func TestSetFileContextDoesNotFollowFinalSymlink(t *testing.T) {
	rootfs := newRootfs(t)
	policy := writePolicyFile(t, `/etc/passwd system_u:object_r:passwd_t:s0
/etc/passwd-link -l system_u:object_r:link_t:s0
`)
	stubFileContexts(t, policy)
	stubFileContextsEnabled(t, true)
	store := newFakeLabelStore(t)

	// Labeling a symlink without FollowSymlinks must set the link's own
	// label, not the target's.
	res, err := SetFileContext("etc/passwd-link", "system_u:object_r:link_t:s0", &FileContextOptions{Rootfs: rootfs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Applied {
		t.Error("Applied = false, want true")
	}
	if got, want := store.get(filepath.Join(rootfs, "etc", "passwd-link")), "system_u:object_r:link_t:s0"; got != want {
		t.Errorf("link label = %q, want %q", got, want)
	}
	if got := store.get(filepath.Join(rootfs, "etc", "passwd")); got != "" {
		t.Errorf("target label = %q, want it untouched", got)
	}
}
