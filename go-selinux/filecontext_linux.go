package selinux

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

// fileContextRule describes one compiled entry of a file_contexts file.
type fileContextRule struct {
	re *regexp.Regexp
	// pattern is the rule text as written in the policy file.
	pattern string
	// stem is the literal prefix of pattern, before the first unescaped
	// regular expression metacharacter.
	stem string
	// context is the raw context column; "<<none>>" is kept as-is and means
	// "do not label".
	context string
	// order is the position of the rule in the concatenated set of policy
	// files. Later rules win ties, mirroring libselinux's behavior for
	// regex entries.
	order int
	// kind is 0 when the rule applies to all file types, otherwise one of
	// the type bytes used by file_contexts ('-', 'd', 'l', ...).
	kind byte
	// hasMeta reports whether pattern contains a regular expression
	// metacharacter.
	hasMeta bool
}

// fileContextsFile returns the base file_contexts file of the current policy.
// It is a variable so tests can point it at a temporary policy.
var fileContextsFile = func() string {
	return filepath.Join(policyRoot(), "contexts", "files", "file_contexts")
}

// fileContextsFiles returns all policy files to load, lowest priority first.
// The optional .homedirs and .local files, when present, override the base
// file, as they do in libselinux.
var fileContextsFiles = func() []string {
	base := fileContextsFile()
	return []string{base, base + ".homedirs", base + ".local"}
}

// fileContextsEnabled reports whether labels can be applied. It is a
// variable so tests can exercise the apply paths on hosts without SELinux.
var fileContextsEnabled = getEnabled

// readFileContextXattr reads the security.selinux xattr of path. When follow
// is false the final symbolic link is not followed.
var readFileContextXattr = func(path string, follow bool) (string, error) {
	var (
		val []byte
		err error
	)
	if follow {
		val, err = getxattr(path, xattrNameSelinux)
	} else {
		val, err = lgetxattr(path, xattrNameSelinux)
	}
	if err != nil {
		return "", &os.PathError{Op: "getxattr", Path: path, Err: err}
	}
	return trimXattrNUL(val), nil
}

// writeFileContextXattr writes the security.selinux xattr of path. When
// follow is false the final symbolic link is not followed.
var writeFileContextXattr = func(path, context string, follow bool) error {
	if follow {
		return setFileLabel(path, context)
	}
	return lSetFileLabel(path, context)
}

func trimXattrNUL(val []byte) string {
	if len(val) > 0 && val[len(val)-1] == '\x00' {
		val = val[:len(val)-1]
	}
	return string(val)
}

// fileContextsCache caches the compiled rules together with a signature of
// the policy files they came from.
var fileContextsCache = struct { //nolint:govet // field alignment is not worth obscuring the cache here
	sync.Mutex
	rules     []fileContextRule
	signature string
}{}

// fileContextsSignature returns a value that changes when the size or
// modification time of any policy file changes.
func fileContextsSignature(files []string) string {
	var b strings.Builder
	for _, file := range files {
		st, err := os.Stat(file)
		if err != nil {
			fmt.Fprintf(&b, "%s:missing:%v;", file, err)
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", file, st.Size(), st.ModTime().UnixNano())
	}
	return b.String()
}

// loadFileContextRules reads and compiles the policy files.
func loadFileContextRules(files []string) ([]fileContextRule, error) {
	var rules []fileContextRule
	// The first file is required; the optional overrides may be missing.
	for i, file := range files {
		f, err := os.Open(file)
		if err != nil {
			if i == 0 {
				return nil, &os.PathError{Op: "open", Path: file, Err: err}
			}
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, &os.PathError{Op: "open", Path: file, Err: err}
		}
		err = parseFileContextRules(f, &rules)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
	}
	return rules, nil
}

// parseFileContextRules appends the entries of one file_contexts file to
// rules. Malformed lines are skipped so that one bad entry does not make the
// whole policy unusable, matching the tolerant behavior of restorecon(8).
func parseFileContextRules(r *os.File, rules *[]fileContextRule) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			// Not enough columns; ignore the line.
			continue
		}
		pattern, context := fields[0], fields[1]
		var kind byte
		if len(fields[1]) == 2 && fields[1][0] == '-' {
			// The optional second column restricts a rule to one file type.
			// An unknown type makes the whole entry invalid, as in
			// libselinux, so it is skipped rather than misinterpreted.
			if !isFileKindColumn(fields[1]) || len(fields) < 3 {
				continue
			}
			kind = fields[1][1]
			context = fields[2]
		}
		re, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			continue
		}
		stem, hasMeta := patternLiteralPrefix(pattern)
		*rules = append(*rules, fileContextRule{
			pattern: pattern,
			re:      re,
			kind:    kind,
			context: context,
			stem:    stem,
			hasMeta: hasMeta,
			order:   len(*rules),
		})
	}
	return scanner.Err()
}

// isFileKindColumn reports whether col is the optional file type column of a
// file_contexts entry, such as "-d" or "-l".
func isFileKindColumn(col string) bool {
	if len(col) != 2 || col[0] != '-' {
		return false
	}
	switch col[1] {
	case 'b', 'c', 'd', 'p', 'l', 's', '-':
		return true
	}
	return false
}

// patternLiteralPrefix returns the literal prefix of pattern (the part
// before the first unescaped regular expression metacharacter) and whether
// the pattern contains a metacharacter at all. Escaped metacharacters are
// unescaped in the returned prefix.
func patternLiteralPrefix(pattern string) (string, bool) {
	var b strings.Builder
	escaped := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if strings.IndexByte(`.^$*+?()[]{}|`, c) >= 0 {
			return b.String(), true
		}
		b.WriteByte(c)
	}
	if escaped {
		// A trailing backslash is not a valid escape; treat the pattern as
		// if it had no literal prefix.
		return b.String(), true
	}
	return b.String(), false
}

// compiledFileContextRules returns the rules of the current policy,
// recompiling them when the policy files changed.
func compiledFileContextRules() ([]fileContextRule, error) {
	files := fileContextsFiles()
	signature := fileContextsSignature(files)

	fileContextsCache.Lock()
	defer fileContextsCache.Unlock()
	if fileContextsCache.rules != nil && fileContextsCache.signature == signature {
		return fileContextsCache.rules, nil
	}
	rules, err := loadFileContextRules(files)
	if err != nil {
		return nil, err
	}
	fileContextsCache.rules = rules
	fileContextsCache.signature = signature
	return rules, nil
}

// flushFileContextCache drops the compiled rule cache.
func flushFileContextCache() {
	fileContextsCache.Lock()
	fileContextsCache.rules = nil
	fileContextsCache.signature = ""
	fileContextsCache.Unlock()
}

// ruleMoreSpecific reports whether a should win over b when both match the
// same path. The comparison approximates libselinux's "most specific match
// wins" rule: a longer literal prefix selects a deeper policy node, a literal
// entry beats a regular expression with the same prefix, and among otherwise
// equal entries the one defined last wins.
func ruleMoreSpecific(a, b *fileContextRule) bool {
	if len(a.stem) != len(b.stem) {
		return len(a.stem) > len(b.stem)
	}
	if a.hasMeta != b.hasMeta {
		return !a.hasMeta
	}
	return a.order > b.order
}

// matchFileContextRule selects the policy rule for a policy path and file
// kind. kind is 0 when the file type is unknown.
func matchFileContextRule(policyPath string, kind byte) (*fileContextRule, error) {
	rules, err := compiledFileContextRules()
	if err != nil {
		return nil, err
	}
	var best *fileContextRule
	for i := range rules {
		rule := &rules[i]
		if rule.kind != 0 && kind != 0 && rule.kind != kind {
			continue
		}
		if !rule.re.MatchString(policyPath) {
			continue
		}
		if best == nil || ruleMoreSpecific(rule, best) {
			best = rule
		}
	}
	return best, nil
}

// fileKindOf returns the file_contexts type byte for path and whether the
// path exists. When follow is false the path itself is inspected, so a
// symbolic link reports 'l'. A missing or uninspectable path reports 0
// (unknown), which matches any rule.
func fileKindOf(path string, follow bool) (byte, bool) {
	var (
		fi  os.FileInfo
		err error
	)
	if follow {
		fi, err = os.Stat(path)
	} else {
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return 0, false
	}
	mode := fi.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		return 'l', true
	case mode.IsDir():
		return 'd', true
	case mode.IsRegular():
		return '-', true
	case mode&os.ModeNamedPipe != 0:
		return 'p', true
	case mode&os.ModeSocket != 0:
		return 's', true
	case mode&os.ModeCharDevice != 0:
		return 'c', true
	case mode&os.ModeDevice != 0:
		return 'b', true
	}
	return 0, true
}

// normalizeOptions returns a copy of opts with defaults applied.
func normalizeOptions(opts *FileContextOptions) FileContextOptions {
	if opts == nil {
		return FileContextOptions{}
	}
	return *opts
}

// resolveFileContext binds fpath to the caller's rootfs and applies the
// symlink policy, reporting both the original and the resolved path.
func resolveFileContext(fpath string, opts FileContextOptions) (*FileContextResult, error) {
	if fpath == "" {
		return nil, ErrEmptyPath
	}

	root := opts.Rootfs
	hostPath := false
	if root == "" {
		if !filepath.IsAbs(fpath) {
			return nil, fmt.Errorf("%w: %q", ErrRelativePathWithoutRootfs, fpath)
		}
		root = string(filepath.Separator)
		hostPath = true
	} else {
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidRootfs, root)
		}
		root = filepath.Clean(root)
		hostPath = root == string(filepath.Separator)
	}

	var resolved string
	var err error
	switch {
	case opts.FollowSymlinks:
		// Resolve every component, treating absolute symlink targets as
		// relative to root, exactly like a chroot, and tolerate components
		// that do not exist yet.
		resolved, err = securejoin.SecureJoin(root, fpath)
	case hostPath && filepath.IsAbs(fpath):
		// A plain absolute host path without symlink following keeps the
		// historical behavior: the path is used as given, only cleaned
		// lexically. Intermediate symlinks are still traversed by the
		// kernel, and the final component is not followed.
		resolved = filepath.Clean(fpath)
	case hostPath:
		// A relative path with an explicit "/" rootfs is still anchored at
		// the host root.
		resolved, err = securejoin.SecureJoin(root, fpath)
	default:
		// Resolve the directory portion so that intermediate symlinks can
		// not move the operation outside of root, but leave the final
		// component unresolved: if it is a symlink, it is the link itself
		// that is inspected or labeled.
		dir, base := filepath.Split(fpath)
		if base == "" || base == "." || base == ".." {
			// A trailing separator or ".." carries no file of its own;
			// resolve it fully, like the kernel would.
			resolved, err = securejoin.SecureJoin(root, fpath)
		} else {
			var resolvedDir string
			resolvedDir, err = securejoin.SecureJoin(root, dir)
			if err == nil {
				resolved = filepath.Join(resolvedDir, base)
			}
		}
	}
	if err != nil {
		return nil, &os.PathError{Op: "resolve", Path: fpath, Err: err}
	}

	// The policy always sees an absolute path. When a rootfs was given, the
	// resolved host path is translated back to the path as seen inside the
	// rootfs; otherwise it already is the host path. Using the resolved path
	// means resolved intermediate components are reflected, so a directory
	// symlink is matched by the path it really points at, not by the link
	// spelling.
	policyPath := filepath.ToSlash(resolved)
	if !hostPath {
		rel, relErr := filepath.Rel(root, resolved)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, &os.PathError{Op: "resolve", Path: fpath, Err: ErrInvalidRootfs}
		}
		policyPath = "/"
		if rel != "." {
			policyPath = "/" + filepath.ToSlash(rel)
		}
	}

	return &FileContextResult{
		Path:           fpath,
		Rootfs:         opts.Rootfs,
		ResolvedPath:   resolved,
		PolicyPath:     policyPath,
		FollowSymlinks: opts.FollowSymlinks,
	}, nil
}

// lookupFileContext implements [LookupFileContext].
func lookupFileContext(fpath string, opts *FileContextOptions) (*FileContextResult, error) {
	o := normalizeOptions(opts)
	res, err := resolveFileContext(fpath, o)
	if err != nil {
		return nil, err
	}
	kind, exists := fileKindOf(res.ResolvedPath, o.FollowSymlinks)
	res.Missing = !exists
	rule, err := matchFileContextRule(res.PolicyPath, kind)
	if err != nil {
		return res, err
	}
	if rule == nil {
		return res, fmt.Errorf("%w: %q (resolved to %q)", ErrContextMissing, fpath, res.ResolvedPath)
	}
	res.Rule = rule.pattern
	res.Context = rule.context
	if res.Context == "<<none>>" {
		// A matching rule that explicitly says "do not label" must not be
		// mistaken for a request to clear an existing label.
		res.Context = ""
	}
	return res, nil
}

// applyFileContext implements [ApplyFileContext].
func applyFileContext(fpath string, opts *FileContextOptions) (*FileContextResult, error) {
	res, err := lookupFileContext(fpath, opts)
	if err != nil {
		// The result still carries the resolved and policy paths, so the
		// caller can diagnose why no rule matched.
		return res, err
	}
	return setFileContextLabel(res, res.Context, normalizeOptions(opts))
}

// setFileContext implements [SetFileContext].
func setFileContext(fpath, context string, opts *FileContextOptions) (*FileContextResult, error) {
	o := normalizeOptions(opts)
	res, err := resolveFileContext(fpath, o)
	if err != nil {
		return nil, err
	}
	if context == "<<none>>" {
		context = ""
	}
	return setFileContextLabel(res, context, o)
}

// setFileContextLabel applies context to the resolved path of res, honoring
// the conflict policy. An empty context means "keep the existing label".
func setFileContextLabel(res *FileContextResult, context string, opts FileContextOptions) (*FileContextResult, error) {
	if res == nil {
		return nil, ErrEmptyPath
	}
	res.Context = context

	if res.Missing {
		// Nothing exists to label. The policy label is still reported, but
		// no xattr is read or written.
		return res, nil
	}

	// Read the existing label first, so that its presence is reported even
	// when no write is needed, and so that it is never replaced silently.
	existing, readErr := readFileContextXattr(res.ResolvedPath, opts.FollowSymlinks)
	switch {
	case readErr == nil:
		res.ExistingContext = existing
	case errors.Is(readErr, unix.ENODATA), errors.Is(readErr, unix.EOPNOTSUPP):
		// No label (or no xattr support) means there is nothing to keep and
		// nothing to conflict with; a label may be written below.
	case errors.Is(readErr, fs.ErrNotExist):
		// The file disappeared between resolution and the xattr read. Like
		// chcon(1), tolerate this: relabeling races with removal, and there
		// is nothing left to label.
		res.Missing = true
		return res, nil
	default:
		return res, readErr
	}

	if context == "" {
		// Empty context means "leave the file as it is"; it never means
		// "remove the label".
		return res, nil
	}
	if !fileContextsEnabled() {
		// SELinux is not in use on this host; applying a label is a no-op,
		// but the caller still learns which label would have been applied.
		return res, nil
	}
	if existing != "" && existing != context {
		switch opts.Conflict {
		case FileContextConflictDeny:
			return res, &FileContextConflictError{
				Path:         res.Path,
				ResolvedPath: res.ResolvedPath,
				Existing:     existing,
				Context:      context,
			}
		case FileContextConflictKeep:
			return res, nil
		case FileContextConflictOverwrite:
			// Explicitly requested; replace below.
		default:
			return res, fmt.Errorf("%w: unknown conflict policy %d", ErrFileContextConflict, opts.Conflict)
		}
	}
	if existing == context {
		return res, nil
	}
	if err := writeFileContextXattr(res.ResolvedPath, context, opts.FollowSymlinks); err != nil {
		return res, err
	}
	res.Applied = true
	res.ExistingContext = existing
	return res, nil
}
