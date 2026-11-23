//go:build !linux

package label

import "errors"

// ErrLabelTransitionDenied mirrors the linux definition so callers can use
// errors.Is on every platform. It is never returned here, as SELinux is not
// available outside Linux.
var ErrLabelTransitionDenied = errors.New("SELinux process label transition denied by policy")

// SetProcessLabel is a no-op on platforms without SELinux: it touches no
// kernel state and therefore cannot leave partial state behind.
func SetProcessLabel(string) error {
	return nil
}
