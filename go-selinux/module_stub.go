//go:build !linux

package selinux

import "errors"

// unavailableModuleBackend is used on platforms without SELinux support:
// every operation reports that policy management is unavailable.
type unavailableModuleBackend struct{}

func defaultModuleBackend() moduleBackend {
	return unavailableModuleBackend{}
}

func (unavailableModuleBackend) available() error {
	return errors.New("SELinux is not supported on this platform")
}

func (unavailableModuleBackend) listInstalled() ([]string, error) {
	return nil, errors.New("SELinux is not supported on this platform")
}

func (unavailableModuleBackend) install(ModuleSpec) error {
	return errors.New("SELinux is not supported on this platform")
}

func (unavailableModuleBackend) remove(string) error {
	return errors.New("SELinux is not supported on this platform")
}
