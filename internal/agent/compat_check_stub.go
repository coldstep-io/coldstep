//go:build !linux

package agent

import "github.com/coldstep-io/coldstep/internal/telemetry"

// CheckRunnerCompat is a no-op on non-Linux platforms. The compat checks
// inspect Linux-specific paths (/sys/fs/cgroup, /proc/1/cgroup, /.dockerenv);
// returning an empty slice lets cross-platform callers compile.
func CheckRunnerCompat() []telemetry.CompatWarning {
	return nil
}
