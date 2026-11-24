//go:build !linux

package selinux

// BindSocket is not supported on non-Linux platforms.
func BindSocket(uintptr) (*SocketContext, error) {
	return nil, ErrSELinuxDisabled
}

// PeerLabel is not supported on non-Linux platforms.
func (s *SocketContext) PeerLabel() (string, error) {
	return "", ErrSELinuxDisabled
}

// SocketWithLabel is not supported on non-Linux platforms.
func SocketWithLabel(int, int, int, string) (uintptr, error) {
	return ^uintptr(0), ErrSELinuxDisabled
}
