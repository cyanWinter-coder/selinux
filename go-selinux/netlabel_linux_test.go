package selinux

import (
	"errors"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func socketPair(t *testing.T) (fd0, fd1 int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		unix.Close(fds[0])
		unix.Close(fds[1])
	})
	return fds[0], fds[1]
}

func TestBindSocketBadFD(t *testing.T) {
	// ^uintptr(0) converts to fd -1, which is never valid.
	if _, err := BindSocket(^uintptr(0)); !errors.Is(err, ErrSocketClosed) {
		t.Fatalf("expected ErrSocketClosed, got %v", err)
	}
}

func TestSocketContextCloseStableError(t *testing.T) {
	fd0, _ := socketPair(t)

	sc, err := BindSocket(uintptr(fd0))
	if err != nil {
		t.Fatal(err)
	}
	if sc.FD() != uintptr(fd0) {
		t.Fatalf("FD: want %d, got %d", fd0, sc.FD())
	}
	if err := sc.Close(); err != nil {
		t.Fatal(err)
	}
	// Close is idempotent.
	if err := sc.Close(); err != nil {
		t.Fatal(err)
	}
	// Queries after Close return a stable error.
	for i := 0; i < 2; i++ {
		if _, err := sc.PeerLabel(); !errors.Is(err, ErrSocketClosed) {
			t.Fatalf("query %d after Close: expected ErrSocketClosed, got %v", i, err)
		}
	}
}

func TestSocketContextClosedFD(t *testing.T) {
	fd0, _ := socketPair(t)

	sc, err := BindSocket(uintptr(fd0))
	if err != nil {
		t.Fatal(err)
	}
	// Close the descriptor behind the handle's back.
	if err := unix.Close(fd0); err != nil {
		t.Fatal(err)
	}
	// The query must not succeed; depending on whether the fd number was
	// already recycled, the handle reports a closed or a stale socket.
	_, err = sc.PeerLabel()
	if !errors.Is(err, ErrSocketClosed) && !errors.Is(err, ErrStaleSocket) {
		t.Fatalf("expected ErrSocketClosed or ErrStaleSocket, got %v", err)
	}
}

func TestSocketContextFDReuse(t *testing.T) {
	fd0, _ := socketPair(t)

	sc, err := BindSocket(uintptr(fd0))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd0); err != nil {
		t.Fatal(err)
	}

	// Reallocate the same descriptor number for an unrelated socket.
	newFd := -1
	for i := 0; i < 64; i++ {
		f, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if f == fd0 {
			newFd = f
			break
		}
		unix.Close(f)
	}
	if newFd < 0 {
		t.Skip("could not reallocate the original fd number")
	}
	defer unix.Close(newFd)

	// The old handle must not observe the new connection's context.
	if _, err := sc.PeerLabel(); !errors.Is(err, ErrStaleSocket) {
		t.Fatalf("expected ErrStaleSocket after fd reuse, got %v", err)
	}
}

func TestSocketContextPeerLabel(t *testing.T) {
	fd0, _ := socketPair(t)

	sc, err := BindSocket(uintptr(fd0))
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	label, err := sc.PeerLabel()
	if !GetEnabled() {
		if !errors.Is(err, ErrSELinuxDisabled) {
			t.Fatalf("expected ErrSELinuxDisabled, got %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if label == "" {
		t.Fatal("expected a non-empty peer label")
	}
	// A second call is served from the cache and agrees with the first.
	label2, err := sc.PeerLabel()
	if err != nil {
		t.Fatal(err)
	}
	if label != label2 {
		t.Fatalf("cached label %q != %q", label2, label)
	}
	// The result matches the legacy helper.
	legacy, err := PeerLabel(uintptr(fd0))
	if err != nil {
		t.Fatal(err)
	}
	if label != legacy {
		t.Fatalf("SocketContext label %q != PeerLabel %q", label, legacy)
	}
}

func TestPeerLabelCompat(t *testing.T) {
	fd0, _ := socketPair(t)

	label, err := PeerLabel(uintptr(fd0))
	if !GetEnabled() {
		// Behavior with SELinux disabled is kernel-dependent (some
		// kernels fail SO_PEERSEC, others report "unlabeled"); the
		// legacy helper must simply not crash.
		t.Logf("PeerLabel with SELinux disabled: %q, %v", label, err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if label == "" {
		t.Fatal("expected a non-empty peer label")
	}
}

func TestClassifyPeerLabelError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"closed fd", unix.EBADF, ErrSocketClosed},
		{"denied EACCES", unix.EACCES, ErrPeerLabelDenied},
		{"denied EPERM", unix.EPERM, ErrPeerLabelDenied},
		{"missing ENODATA", unix.ENODATA, ErrPeerLabelMissing},
		{"missing ENOPROTOOPT", unix.ENOPROTOOPT, ErrPeerLabelMissing},
		{"wrapped", &os.PathError{Op: "getsockopt", Path: "fd 3", Err: unix.ENODATA}, ErrPeerLabelMissing},
		{"other", unix.EIO, unix.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPeerLabelError(tc.err); !errors.Is(got, tc.want) {
				t.Fatalf("classifyPeerLabelError(%v): want %v, got %v", tc.err, tc.want, got)
			}
		})
	}
}

func TestPeerContextCacheBound(t *testing.T) {
	// Use fd numbers far away from any real descriptor.
	const base = 1 << 20

	SetPeerContextCacheLimit(4)
	defer SetPeerContextCacheLimit(defaultPeerContextCacheLimit)

	for i := 0; i < 32; i++ {
		peerContexts.add(base+i, uint64(i), uint64(i), "ctx")
	}
	if got := peerContexts.size(); got > 4 {
		t.Fatalf("cache size %d exceeds limit 4", got)
	}
	// The oldest entries were evicted first.
	if _, ok := peerContexts.get(base+0, 0, 0); ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := peerContexts.get(base+31, 31, 31); !ok {
		t.Fatal("newest entry should be cached")
	}

	// An entry is never served for a different generation of the same fd.
	if _, ok := peerContexts.get(base+31, 999, 999); ok {
		t.Fatal("cache served a context across fd generations")
	}

	// remove only affects the matching generation.
	peerContexts.remove(base+31, 999, 999)
	if _, ok := peerContexts.get(base+31, 31, 31); !ok {
		t.Fatal("remove with a foreign generation evicted the entry")
	}
	peerContexts.remove(base+31, 31, 31)
	if _, ok := peerContexts.get(base+31, 31, 31); ok {
		t.Fatal("remove did not evict the entry")
	}

	// A non-positive limit disables caching entirely.
	SetPeerContextCacheLimit(0)
	peerContexts.add(base+100, 1, 1, "ctx")
	if got := peerContexts.size(); got != 0 {
		t.Fatalf("cache size %d with disabled cache", got)
	}
}

func TestSocketContextConcurrentClose(t *testing.T) {
	fd0, _ := socketPair(t)

	sc, err := BindSocket(uintptr(fd0))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, err := sc.PeerLabel()
				switch {
				case err == nil:
				case errors.Is(err, ErrSocketClosed),
					errors.Is(err, ErrStaleSocket),
					errors.Is(err, ErrSELinuxDisabled),
					errors.Is(err, ErrPeerLabelMissing),
					errors.Is(err, ErrPeerLabelDenied):
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			if err := sc.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}
	}()
	wg.Wait()

	// After the dust settles, the closed handle reports a stable error.
	if _, err := sc.PeerLabel(); !errors.Is(err, ErrSocketClosed) {
		t.Fatalf("expected ErrSocketClosed, got %v", err)
	}
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestSocketWithLabelFailureNoLeak(t *testing.T) {
	before := countOpenFDs(t)

	fd, err := SocketWithLabel(unix.AF_UNIX, unix.SOCK_STREAM, 0, "not_a_valid_label")
	if !GetEnabled() {
		if !errors.Is(err, ErrSELinuxDisabled) {
			t.Fatalf("expected ErrSELinuxDisabled, got %v", err)
		}
	} else if err == nil {
		unix.Close(int(fd))
		t.Fatal("expected an error for an invalid label")
	}
	if fd != ^uintptr(0) {
		t.Fatalf("expected invalid fd on failure, got %d", fd)
	}
	if after := countOpenFDs(t); after > before {
		t.Fatalf("file descriptor leaked: before=%d after=%d", before, after)
	}
}

func TestSocketWithLabelEmpty(t *testing.T) {
	// An empty label works regardless of SELinux state and yields a
	// usable socket the caller can close.
	fd, err := SocketWithLabel(unix.AF_UNIX, unix.SOCK_STREAM, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(int(fd)); err != nil {
		t.Fatal(err)
	}
}

func TestSocketWithLabelValid(t *testing.T) {
	if !GetEnabled() {
		t.Skip("SELinux not enabled, skipping.")
	}

	// The process's own context is always a valid label.
	label, err := CurrentLabel()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := SocketWithLabel(unix.AF_UNIX, unix.SOCK_STREAM, 0, label)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(int(fd))

	// The socket is bound to its own generation and can be queried.
	sc, err := BindSocket(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if _, err := sc.PeerLabel(); err != nil && !errors.Is(err, ErrPeerLabelMissing) {
		// An unconnected socket has no peer; anything else is a bug.
		t.Fatalf("unexpected PeerLabel error: %v", err)
	}
}
