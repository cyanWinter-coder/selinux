package selinux

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

// semoduleBin is the policy management tool invoked by the real module
// backend.
const semoduleBin = "semodule"

// semoduleBackend manages SELinux policy modules through the semodule(8)
// command line tool.
type semoduleBackend struct {
	bin string
}

func defaultModuleBackend() moduleBackend {
	backend := &semoduleBackend{}
	if path, err := exec.LookPath(semoduleBin); err == nil {
		backend.bin = path
	}
	return backend
}

// available makes sure SELinux is enabled and the semodule tool is present
// before any policy change is attempted.
func (b *semoduleBackend) available() error {
	if !GetEnabled() {
		return errors.New("SELinux is not enabled")
	}
	if b.bin == "" {
		return errors.New(semoduleBin + " executable not found in PATH")
	}
	return nil
}

// listInstalled parses the output of "semodule --list-modules=full". Modern
// releases print one module per line ("module_name  version"), older ones
// print a fixed-width table. The first whitespace-delimited field is the
// module name in both formats.
func (b *semoduleBackend) listInstalled() ([]string, error) {
	out, err := b.run("--list-modules=full")
	if err != nil {
		return nil, err
	}
	var modules []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name := strings.Fields(line)[0]
		// Skip explanatory header lines emitted by some semodule versions.
		if !validModuleName(name) {
			continue
		}
		modules = append(modules, name)
	}
	return modules, nil
}

func (b *semoduleBackend) install(mod ModuleSpec) error {
	_, err := b.run("--install", mod.Path)
	return err
}

func (b *semoduleBackend) remove(name string) error {
	_, err := b.run("--remove", name)
	return err
}

// run executes semodule with the given arguments and returns its standard
// output. Standard error is folded into the returned error so the system's
// rejection reason is not lost.
func (b *semoduleBackend) run(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(b.bin, args...) // #nosec G204 -- semodule path and arguments are package-controlled.
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", err
		}
		return "", errors.New(err.Error() + ": " + msg)
	}
	return stdout.String(), nil
}
