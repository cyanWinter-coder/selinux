package selinux

import (
	"bufio"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// This file implements a cache for file context lookups: given a path, it
// returns the file context label that the currently loaded SELinux policy
// associates with it (the equivalent of matchpathcon(3)).
//
// A long-running process can not keep the lookup results forever: reloading
// the SELinux policy (load_policy(8), semodule(8), ...) may change the file
// context definitions, after which previously computed labels are stale. To
// handle that, every cache entry is tied to the SELinux policy generation:
// once the generation changes, old entries no longer match and are dropped.

// policyGeneration returns a number identifying the generation of the
// currently loaded SELinux policy. The value is the sequence number the
// kernel exports via selinuxfs, which is incremented every time the policy
// is reloaded (as well as on a few other status changes), so a change of the
// value means the file context definitions may have changed.
//
// It returns 0 when the generation can not be determined (for example when
// SELinux is disabled); in that case cached entries are never invalidated by
// policy changes.
//
// It is a variable to allow tests to substitute a fake generation source.
var policyGeneration = func() uint64 {
	mnt := getSelinuxMountPoint()
	if mnt == "" {
		return 0
	}
	status, err := os.ReadFile(filepath.Join(mnt, "status"))
	if err != nil {
		return 0
	}
	// The status file contains struct selinux_kernel_status:
	//	__u32 version;	/* offset 0 */
	//	__u32 sequence;	/* offset 4 */
	//	...
	const seqOff = 4
	if len(status) < seqOff+4 {
		return 0
	}
	return uint64(binary.LittleEndian.Uint32(status[seqOff:]))
}

// fileContextSpec is a single compiled entry of a file_contexts file.
type fileContextSpec struct {
	re   *regexp.Regexp
	stem string
	con  string
}

// fileContextsFile returns the path of the file_contexts file of the current
// policy. It is a variable to allow tests to substitute a temporary file.
var fileContextsFile = func() string {
	return filepath.Join(policyRoot(), "contexts", "files", "file_contexts")
}

// patternStem returns the literal prefix of pattern, i.e. the part before
// the first regular expression meta-character. It is used to approximate
// libselinux's "most specific match wins" rule.
func patternStem(pattern string) string {
	if i := strings.IndexAny(pattern, `\.^$*+?()[]{}|`); i >= 0 {
		return pattern[:i]
	}
	return pattern
}

// loadFileContextSpecs reads and compiles the file_contexts file of the
// current policy.
//
// This is a simplified re-implementation of libselinux's matchpathcon
// backend, with the following differences:
//   - only the plain-text file_contexts file is used (the pre-compiled .bin
//     variant, and the .subs/.subs_dist, local and homedir files are not
//     consulted);
//   - the optional file type column is ignored, i.e. entries match
//     regardless of the file type;
//   - entries with a "<<none>>" context, and entries whose pattern can not
//     be compiled by Go's regexp package, are skipped.
func loadFileContextSpecs() ([]fileContextSpec, error) {
	f, err := os.Open(fileContextsFile())
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var specs []fileContextSpec
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			// Skip blank lines and comments.
			continue
		}
		fields := strings.Fields(line)
		var pattern, con string
		switch len(fields) {
		case 2: // <regex> <context>
			pattern, con = fields[0], fields[1]
		case 3: // <regex> <file type> <context>
			pattern, con = fields[0], fields[2]
		default:
			// Skip malformed lines.
			continue
		}
		if con == "<<none>>" {
			continue
		}
		// Like libselinux, require the pattern to match the whole path.
		re, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			continue
		}
		specs = append(specs, fileContextSpec{
			re:   re,
			stem: patternStem(pattern),
			con:  con,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return specs, nil
}

// specsCache caches the compiled file_contexts entries for one policy
// generation.
var specsCache = struct {
	sync.Mutex
	gen   uint64
	specs []fileContextSpec
}{}

// compiledFileContextSpecs returns the compiled file_contexts entries for
// the current policy generation, reloading them from disk when the policy
// generation has changed. Load errors are returned to the caller and are
// deliberately not cached, so a subsequent call retries the load instead of
// sticking with a permanent failure.
func compiledFileContextSpecs() ([]fileContextSpec, error) {
	gen := policyGeneration()

	specsCache.Lock()
	defer specsCache.Unlock()
	if specsCache.specs != nil && specsCache.gen == gen {
		return specsCache.specs, nil
	}
	specs, err := loadFileContextSpecs()
	if err != nil {
		return nil, err
	}
	specsCache.gen = gen
	specsCache.specs = specs
	return specs, nil
}

// matchFileContext performs the underlying (uncached) file context match for
// fpath against the file_contexts definitions of the current policy. It
// returns ErrContextMissing if no entry matches fpath.
//
// It is a variable to allow tests to substitute a fake matcher.
var matchFileContext = func(fpath string) (string, error) {
	specs, err := compiledFileContextSpecs()
	if err != nil {
		return "", err
	}
	best := -1
	for i := range specs {
		if !specs[i].re.MatchString(fpath) {
			continue
		}
		// The entry with the longest literal prefix (stem) wins, which
		// approximates libselinux's "most specific match" rule.
		if best < 0 || len(specs[i].stem) > len(specs[best].stem) {
			best = i
		}
	}
	if best < 0 {
		return "", ErrContextMissing
	}
	return specs[best].con, nil
}

// fileConCall represents an in-flight file context lookup, allowing
// concurrent lookups of the same path within one policy generation to share
// a single underlying match.
type fileConCall struct {
	done  chan struct{}
	label string
	err   error
	epoch uint64
}

// fileConCache caches file context labels for one policy generation. The
// cached entries are only valid while fileConCache.gen matches the current
// policy generation; epoch is bumped on every generation change and every
// explicit flush, and is used to avoid storing results of lookups that were
// started before either of those events.
var fileConCache = struct {
	sync.Mutex
	gen      uint64
	epoch    uint64
	entries  map[string]string
	inflight map[string]*fileConCall
}{
	entries:  make(map[string]string),
	inflight: make(map[string]*fileConCall),
}

// lookupFileContext returns the file context label for fpath, using the
// process-local cache when SELinux is enabled.
func lookupFileContext(fpath string) (string, error) {
	if fpath == "" {
		return "", ErrEmptyPath
	}
	if !getEnabled() {
		// SELinux is disabled: bypass the cache entirely and perform the
		// lookup directly, preserving the behavior of an uncached lookup.
		return matchFileContext(fpath)
	}
	gen := policyGeneration()

	fileConCache.Lock()
	if fileConCache.gen != gen {
		// The policy was reloaded: entries and in-flight lookups from the
		// previous generation are no longer valid.
		fileConCache.gen = gen
		fileConCache.epoch++
		fileConCache.entries = make(map[string]string)
		fileConCache.inflight = make(map[string]*fileConCall)
	}
	if label, ok := fileConCache.entries[fpath]; ok {
		fileConCache.Unlock()
		return label, nil
	}
	if call, ok := fileConCache.inflight[fpath]; ok {
		// Another goroutine is already performing the underlying match for
		// this path in this policy generation; wait for its result instead
		// of duplicating the work.
		fileConCache.Unlock()
		<-call.done
		return call.label, call.err
	}
	call := &fileConCall{done: make(chan struct{}), epoch: fileConCache.epoch}
	fileConCache.inflight[fpath] = call
	fileConCache.Unlock()

	label, err := matchFileContext(fpath)

	fileConCache.Lock()
	if fileConCache.inflight[fpath] == call {
		delete(fileConCache.inflight, fpath)
	}
	if err == nil && call.epoch == fileConCache.epoch {
		// Only successful lookups are cached, and only if neither a policy
		// reload nor an explicit flush happened while the lookup was in
		// flight. Errors (including ErrContextMissing) are never cached, so
		// they can not turn into permanent successes.
		fileConCache.entries[fpath] = label
	}
	call.label, call.err = label, err
	close(call.done)
	fileConCache.Unlock()

	return label, err
}

// flushFileContextCache clears all process-local file context caches. It
// does not reload or otherwise modify the system SELinux policy.
func flushFileContextCache() {
	fileConCache.Lock()
	fileConCache.epoch++
	fileConCache.entries = make(map[string]string)
	fileConCache.inflight = make(map[string]*fileConCall)
	fileConCache.Unlock()

	specsCache.Lock()
	specsCache.specs = nil
	specsCache.Unlock()
}
