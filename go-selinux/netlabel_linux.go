package selinux

import (
	"errors"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// BindSocket binds a [SocketContext] to the current generation of fd,
// which must refer to an open socket. The descriptor itself stays owned by
// the caller; see [SocketContext.Close].
func BindSocket(fd uintptr) (*SocketContext, error) {
	dev, ino, err := socketIdentity(int(fd)) //#nosec G115 -- ignore "integer overflow conversion uintptr -> int".
	if err != nil {
		return nil, err
	}
	return &SocketContext{fd: int(fd), dev: dev, ino: ino}, nil //#nosec G115 -- ignore "integer overflow conversion uintptr -> int".
}

// socketIdentity returns the (device, inode) pair identifying the open
// file description currently referenced by fd. Two sockets never share a
// live (dev, ino) pair, so it acts as the fd's generation: after the fd is
// closed and its number reused, the pair no longer matches.
func socketIdentity(fd int) (dev, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		if errors.Is(err, unix.EBADF) {
			return 0, 0, ErrSocketClosed
		}
		return 0, 0, &os.PathError{Op: "fstat", Path: "fd " + strconv.Itoa(fd), Err: err}
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}

// PeerLabel returns the SELinux label of the peer connected to the socket
// this handle is bound to.
//
// The result is memoized in a bounded cache (see
// [SetPeerContextCacheLimit]) keyed by fd generation, so repeated calls are
// cheap and a cached context is never served to a different connection
// reusing the same descriptor number.
//
// The failure modes are deliberately distinct:
//   - [ErrSocketClosed]: the handle was closed, or the fd is no longer valid;
//   - [ErrStaleSocket]: the fd was closed and reused by another connection;
//   - [ErrSELinuxDisabled]: SELinux is not enabled on this system;
//   - [ErrPeerLabelMissing]: the peer did not present a security context;
//   - [ErrPeerLabelDenied]: the policy denied the query.
func (s *SocketContext) PeerLabel() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrSocketClosed
	}
	// Verify the generation before anything else: if the descriptor was
	// recycled underneath us, no other result would be meaningful.
	dev, ino, err := socketIdentity(s.fd)
	if err != nil {
		return "", err
	}
	if dev != s.dev || ino != s.ino {
		return "", ErrStaleSocket
	}
	if !getEnabled() {
		return "", ErrSELinuxDisabled
	}
	if label, ok := peerContexts.get(s.fd, dev, ino); ok {
		return label, nil
	}
	label, err := peerLabel(s.fd)
	if err != nil {
		return "", classifyPeerLabelError(err)
	}
	if label == "" {
		return "", ErrPeerLabelMissing
	}
	peerContexts.add(s.fd, dev, ino, label)
	return label, nil
}

// classifyPeerLabelError maps low-level SO_PEERSEC failures onto the
// package's stable sentinel errors, so callers can tell a missing context,
// a policy denial and a closed socket apart with errors.Is.
func classifyPeerLabelError(err error) error {
	switch {
	case errors.Is(err, unix.EBADF):
		return ErrSocketClosed
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return ErrPeerLabelDenied
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOPROTOOPT):
		return ErrPeerLabelMissing
	default:
		return err
	}
}

// SocketWithLabel creates a new socket of the given domain, type and
// protocol that carries the given SELinux label, and returns its file
// descriptor. The label is applied through the thread's sockcreate
// attribute, which is reset before the function returns.
//
// If the label cannot be set, no socket is created and no file descriptor
// is leaked; on success the returned descriptor belongs to the caller, who
// may close it safely. Passing an empty label is equivalent to calling
// unix.Socket directly. A non-empty label on a system with SELinux
// disabled fails with [ErrSELinuxDisabled].
func SocketWithLabel(domain, typ, proto int, label string) (uintptr, error) {
	if label != "" && !getEnabled() {
		return ^uintptr(0), ErrSELinuxDisabled
	}
	// The sockcreate attribute is per-thread, so the goroutine must not
	// migrate to another thread between setting the label and creating
	// the socket.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if label != "" {
		if err := SetSocketLabel(label); err != nil {
			return ^uintptr(0), err
		}
		// Restore the default for subsequently created sockets.
		defer func() { _ = SetSocketLabel("") }()
	}
	fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return ^uintptr(0), err
	}
	return uintptr(fd), nil
}
