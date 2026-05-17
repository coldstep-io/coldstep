//go:build !linux

package agent

import "fmt"

// Main is the non-Linux stub for agent.Main. Returns a build-tag error so
// callers on macOS/Windows surface a clear "wrong platform" message instead
// of mysterious BPF load failures. The Linux implementation lives in
// agent_linux.go.
func Main() error {
	return fmt.Errorf("coldstep is supported only on GitHub-hosted ubuntu-latest (amd64) with BPF; build is not linux")
}
