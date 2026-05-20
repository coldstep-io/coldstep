//go:build !linux

package agent

import "github.com/coldstep-io/coldstep/internal/telemetry"

// RunnerEnv* mirrors the Linux constants so cross-platform callers compile
// against a single name. Detection always returns "unknown" off-Linux because
// the heuristic depends on Linux-only /proc/1/cgroup.
const (
	RunnerEnvStandard = "standard"
	RunnerEnvDinD     = "dind"
	RunnerEnvUnknown  = "unknown"
)

// CheckRunnerCompat is a no-op on non-Linux platforms. The compat checks
// inspect Linux-specific paths (/sys/fs/cgroup, /proc/1/cgroup, /.dockerenv);
// returning an empty slice lets cross-platform callers compile.
func CheckRunnerCompat() []telemetry.CompatWarning {
	return nil
}

// DetectRunnerEnv is a no-op stub on non-Linux platforms.
func DetectRunnerEnv() string {
	return RunnerEnvUnknown
}
