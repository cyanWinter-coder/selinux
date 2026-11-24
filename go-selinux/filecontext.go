package selinux

import (
	"errors"
	"fmt"
	"strings"
)

// FileContextConflictPolicy selects what [ApplyFileContext] and
// [SetFileContext] do when the label stored in the security.selinux xattr of
// a file differs from the label they were asked to apply.
type FileContextConflictPolicy int

const (
	// FileContextConflictDeny is the default. A conflict is reported as a
	// [FileContextConflictError] and the on-disk label is left untouched.
	// Security metadata that is already present is never replaced silently.
	FileContextConflictDeny FileContextConflictPolicy = iota
	// FileContextConflictOverwrite replaces the existing label with the
	// requested one.
	FileContextConflictOverwrite
	// FileContextConflictKeep keeps the existing label and reports it in
	// [FileContextResult.ExistingContext].
	FileContextConflictKeep
)

// FileContextOptions control how a path is resolved and matched against the
// SELinux file context policy, and how a resulting label is applied.
//
// The zero value is valid and keeps the historical absolute-path behavior:
// paths are interpreted on the host and symlinks are not followed.
type FileContextOptions struct {
	// Rootfs is the root directory a path is anchored to before it is
	// matched against the policy. When it is set, both relative and absolute
	// paths are interpreted inside Rootfs: "etc/passwd" and "/etc/passwd"
	// both refer to <Rootfs>/etc/passwd, and the policy sees "/etc/passwd".
	// Symlink resolution never escapes Rootfs, including through absolute
	// symlink targets.
	//
	// When Rootfs is empty, only absolute host paths are accepted. Relative
	// paths are rejected with [ErrRelativePathWithoutRootfs] because there is
	// no unambiguous directory to anchor them to.
	Rootfs string
	// FollowSymlinks makes the resolved path - after Rootfs binding - follow
	// symbolic links before matching and labeling. Absolute symlink targets
	// are interpreted relative to Rootfs. When it is false (the default),
	// paths are matched and labeled without resolving symbolic links.
	FollowSymlinks bool
	// Conflict selects how to handle a mismatch between an existing
	// security.selinux xattr and the label that should be applied. The zero
	// value, [FileContextConflictDeny], refuses to overwrite.
	Conflict FileContextConflictPolicy
}

// FileContextResult describes how a caller-supplied path was resolved and
// which label the policy associates with it.
type FileContextResult struct {
	// Path is the path exactly as the caller supplied it.
	Path string
	// Rootfs is the root the path was anchored to. It is empty when the
	// caller did not request a rootfs.
	Rootfs string
	// ResolvedPath is the host path that was actually inspected or labeled.
	// It is inside Rootfs (when one was given) and, if symlinks were
	// followed, points at the symlink target.
	ResolvedPath string
	// PolicyPath is the absolute path as seen inside Rootfs (or on the host
	// when no rootfs was given) that was matched against the policy rules.
	PolicyPath string
	// Rule is the file_contexts pattern of the matching rule. It is empty
	// when no rule matched or when the label was supplied explicitly.
	Rule string
	// Context is the SELinux label obtained from the policy or supplied by
	// the caller. An empty Context means "keep the label that is already on
	// disk"; it never means "remove the label".
	Context string
	// ExistingContext is the label that was on disk before the call. It is
	// populated by [ApplyFileContext] and [SetFileContext].
	ExistingContext string
	// FollowSymlinks reports whether symlinks were resolved.
	FollowSymlinks bool
	// Applied reports whether the call changed the on-disk label.
	Applied bool
	// Missing reports that the resolved path does not exist. Its policy
	// label is still reported, which lets a caller label a file that is
	// about to be created; nothing is written for it.
	Missing bool
}

// FileContextConflictError reports that a file already carries an SELinux
// label that differs from the one that should be applied.
type FileContextConflictError struct {
	// Path is the path as supplied by the caller.
	Path string
	// ResolvedPath is the resolved host path carrying the label.
	ResolvedPath string
	// Existing is the label currently stored in the xattr.
	Existing string
	// Context is the label that was requested or selected by policy.
	Context string
}

// Error implements the error interface.
func (e *FileContextConflictError) Error() string {
	return fmt.Sprintf("%s: %q (resolved to %q) has label %q, refusing to replace it with %q",
		ErrFileContextConflict, e.Path, e.ResolvedPath, e.Existing, e.Context)
}

// Unwrap makes the error match [ErrFileContextConflict] with [errors.Is].
func (e *FileContextConflictError) Unwrap() error {
	return ErrFileContextConflict
}

var (
	// ErrFileContextConflict is matched by [FileContextConflictError] when a
	// file's existing label differs from the label to apply.
	ErrFileContextConflict = errors.New("existing SELinux label conflicts with file context policy")
	// ErrRelativePathWithoutRootfs is returned when a relative path is used
	// without [FileContextOptions.Rootfs].
	ErrRelativePathWithoutRootfs = errors.New("relative path requires a rootfs")
	// ErrInvalidRootfs is returned when [FileContextOptions.Rootfs] is not an
	// absolute path.
	ErrInvalidRootfs = errors.New("rootfs must be an absolute path")
)

// LookupFileContext resolves fpath and returns the SELinux label that the
// currently loaded file context policy associates with it, similar to
// matchpathcon(3).
//
// Resolution happens before matching: a relative path is first anchored to
// [FileContextOptions.Rootfs], then symbolic links are followed only when
// [FileContextOptions.FollowSymlinks] is set, and finally the resulting
// rootfs-relative path - not the host path - is matched against the policy
// rules. Both the original and the resolved path are reported in the result,
// including when no rule matches ([ErrContextMissing]).
//
// A matching rule with an empty context ("<<none>>") yields an empty
// [FileContextResult.Context] and a nil error: it means "leave the file
// alone", not "clear the label". Lookup never touches the filesystem label.
//
// Like matchpathcon(3), the plain-text file_contexts, file_contexts.homedirs
// and file_contexts.local files of the current policy are consulted. The
// precompiled .bin variants and the path substitutions from file_contexts.subs
// / file_contexts.subs_dist are not, so a path is matched as given.
func LookupFileContext(fpath string, opts *FileContextOptions) (*FileContextResult, error) {
	return lookupFileContext(fpath, opts)
}

// ApplyFileContext looks up the policy label for fpath and applies it to the
// file, honoring [FileContextOptions.Conflict].
//
// Before changing anything it reads the existing security.selinux xattr. A
// difference is reported as a [FileContextConflictError] unless the caller
// explicitly selected [FileContextConflictOverwrite] or
// [FileContextConflictKeep], so existing security metadata is never replaced
// silently. An empty label (including a policy match of "<<none>>") leaves
// the file unchanged.
// Applying to a path that does not exist is not an error: the policy label is
// still reported and nothing is written (see [FileContextResult.Missing]).
func ApplyFileContext(fpath string, opts *FileContextOptions) (*FileContextResult, error) {
	return applyFileContext(fpath, opts)
}

// SetFileContext applies context to fpath, using the same conflict handling
// as [ApplyFileContext]. The path is resolved exactly like in
// [LookupFileContext] (rootfs binding and the FollowSymlinks option), but no
// policy lookup is performed.
//
// An empty or "<<none>>" context is a no-op that keeps the existing label; it
// never clears it. This is also true for a missing file: nothing is changed
// and no error is returned, but [FileContextResult.Missing] is set.
func SetFileContext(fpath, context string, opts *FileContextOptions) (*FileContextResult, error) {
	return setFileContext(fpath, strings.TrimSpace(context), opts)
}

// FlushFileContextCache drops the process-local cache of compiled policy
// rules. The cache is also invalidated automatically when the policy files
// change size or modification time; this function is only needed when a
// policy file is rewritten without those changing.
func FlushFileContextCache() {
	flushFileContextCache()
}
