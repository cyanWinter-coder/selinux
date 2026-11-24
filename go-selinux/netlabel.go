package selinux

import (
	"container/list"
	"errors"
	"sync"
)

var (
	// ErrSocketClosed is returned by [SocketContext] methods when the
	// handle has been closed, or when the underlying file descriptor is
	// no longer valid.
	ErrSocketClosed = errors.New("socket context is closed")

	// ErrStaleSocket is returned by [SocketContext] methods when the file
	// descriptor the handle was bound to has been closed and reused by an
	// unrelated connection, so the recorded fd generation no longer
	// matches the live one.
	ErrStaleSocket = errors.New("socket descriptor reused by another connection")

	// ErrPeerLabelMissing is returned when the peer security context is
	// not available for a socket (the peer did not present one, or the
	// socket does not support SO_PEERSEC).
	ErrPeerLabelMissing = errors.New("peer security context is missing")

	// ErrPeerLabelDenied is returned when the SELinux policy denies
	// reading the peer security context of a socket.
	ErrPeerLabelDenied = errors.New("peer security context query denied by policy")

	// ErrSELinuxDisabled is returned when an operation requires SELinux
	// but it is not enabled on the system.
	ErrSELinuxDisabled = errors.New("SELinux is not enabled")
)

// defaultPeerContextCacheLimit is the default upper bound on the number of
// peer security contexts cached by [SocketContext].
const defaultPeerContextCacheLimit = 1024

// peerContextEntry is a cached peer label bound to one fd generation.
type peerContextEntry struct {
	fd    int
	dev   uint64
	ino   uint64
	label string
}

// peerContextCache is a bounded LRU cache of peer labels keyed by fd.
// An entry is only valid for the exact fd generation (dev, ino) it was
// recorded for, so a cached context is never served to a later connection
// that happens to reuse the same descriptor number.
type peerContextCache struct {
	mu      sync.Mutex
	limit   int
	entries map[int]*list.Element
	lru     *list.List // front is most recently used; values are peerContextEntry
}

func newPeerContextCache(limit int) *peerContextCache {
	return &peerContextCache{
		limit:   limit,
		entries: make(map[int]*list.Element),
		lru:     list.New(),
	}
}

func (c *peerContextCache) get(fd int, dev, ino uint64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[fd]
	if !ok {
		return "", false
	}
	e := el.Value.(peerContextEntry)
	if e.dev != dev || e.ino != ino {
		// Same fd number, different generation: never serve the
		// stale context.
		return "", false
	}
	c.lru.MoveToFront(el)
	return e.label, true
}

func (c *peerContextCache) add(fd int, dev, ino uint64, label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limit <= 0 {
		return
	}
	entry := peerContextEntry{fd: fd, dev: dev, ino: ino, label: label}
	if el, ok := c.entries[fd]; ok {
		el.Value = entry
		c.lru.MoveToFront(el)
	} else {
		c.entries[fd] = c.lru.PushFront(entry)
	}
	c.evictLocked()
}

// remove drops the entry for fd only if it still belongs to the given
// generation, so closing an old handle cannot evict the context recorded
// for a newer connection reusing the same descriptor.
func (c *peerContextCache) remove(fd int, dev, ino uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[fd]
	if !ok {
		return
	}
	if e := el.Value.(peerContextEntry); e.dev == dev && e.ino == ino {
		c.lru.Remove(el)
		delete(c.entries, fd)
	}
}

func (c *peerContextCache) setLimit(limit int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.limit = limit
	c.evictLocked()
}

func (c *peerContextCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// evictLocked trims the cache to its limit, evicting the least recently
// used entries first. A non-positive limit empties the cache. The caller
// must hold c.mu.
func (c *peerContextCache) evictLocked() {
	for c.lru.Len() > 0 && (c.limit <= 0 || c.lru.Len() > c.limit) {
		back := c.lru.Back()
		c.lru.Remove(back)
		delete(c.entries, back.Value.(peerContextEntry).fd)
	}
}

var peerContexts = newPeerContextCache(defaultPeerContextCacheLimit)

// SetPeerContextCacheLimit adjusts the maximum number of peer security
// contexts cached by [SocketContext]. A limit of zero or less disables
// caching. The default is 1024 entries.
func SetPeerContextCacheLimit(limit int) {
	peerContexts.setLimit(limit)
}

// SocketContext binds SELinux socket state to one generation of a file
// descriptor. It exists so that a peer context read after the socket was
// closed — or after the descriptor number was reused by another
// connection — fails with a stable error instead of silently returning a
// label that belongs to a different connection.
//
// A SocketContext does not own the file descriptor: [SocketContext.Close]
// invalidates the handle and drops its cached state, but never closes the
// fd itself. Methods are safe for concurrent use.
type SocketContext struct {
	mu     sync.Mutex
	fd     int
	dev    uint64
	ino    uint64
	closed bool
}

// FD returns the file descriptor the handle is bound to.
func (s *SocketContext) FD() uintptr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uintptr(s.fd)
}

// Close invalidates the handle and drops any peer context cached for this
// fd generation. It does not close the underlying file descriptor, which
// remains owned by the caller. Close is idempotent and safe to call
// concurrently with other methods.
func (s *SocketContext) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	peerContexts.remove(s.fd, s.dev, s.ino)
	return nil
}
