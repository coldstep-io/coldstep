//go:build !linux

package actioncli

import "time"

// findAgentPID is a no-op on non-Linux: the action only really runs on Linux,
// but main.go is cross-compiled so the unit tests run on Windows / macOS.
// Returning sudoPid unchanged keeps the build green without breaking semantics
// where the lookup is meaningful.
func findAgentPID(sudoPid int, _ time.Duration) int {
	return sudoPid
}
