//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/coldstep-io/coldstep/internal/telemetry"
	"golang.org/x/sys/unix"
)

// Warning code constants. Kept stable for telemetry consumers.
const (
	CompatCodeCgroupV1Detected         = "cgroup_v1_detected"
	CompatCodeCgroupNamespaceNonDeleg  = "cgroup_namespace_nondelegated"
	CompatCodeDeepCgroupNesting        = "deep_cgroup_nesting"
	CompatCodeContainerCgroupDetection = "container_cgroup_detection_failed"
)

// RunnerEnv* classify the agent's runner environment for the MetaEvent
// runner_env field. Kept stable for downstream telemetry consumers.
const (
	RunnerEnvStandard = "standard"
	RunnerEnvDinD     = "dind"
	RunnerEnvUnknown  = "unknown"
)

// DetectRunnerEnv classifies the agent's runtime environment by reading
// /proc/1/cgroup. The heuristic is intentionally conservative:
//   - any line whose cgroup path segment contains "docker" (case-insensitive)
//     → RunnerEnvDinD (Docker-in-Docker — inner-container traffic is not
//     observable from the outer runner cgroup namespace).
//   - file exists with no docker markers → RunnerEnvStandard.
//   - file missing / unreadable → RunnerEnvUnknown.
//
// A false negative is acceptable (the ⚠️ surfaced in the digest is purely
// informational); a false positive is also acceptable for the same reason.
func DetectRunnerEnv() string {
	content, err := readProc1Cgroup()
	if err != nil {
		return RunnerEnvUnknown
	}
	return classifyRunnerEnv(content)
}

// classifyRunnerEnv is the pure function behind DetectRunnerEnv — split out
// so unit tests can feed synthetic /proc/1/cgroup content without depending
// on the real file. Matches "docker" inside the cgroup path segment (parts[2]
// of each `hierarchy_id:controllers:path` line), not the controller list, so
// e.g. `12:devices:/docker/abc` and `0::/docker/abc/init.scope` both classify
// as DinD.
func classifyRunnerEnv(procCgroup string) string {
	for _, line := range strings.Split(procCgroup, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		if strings.Contains(strings.ToLower(parts[2]), "docker") {
			return RunnerEnvDinD
		}
	}
	return RunnerEnvStandard
}

// deepCgroupNestingThreshold is the depth at which /proc/1/cgroup paths
// are flagged. Hosted Ubuntu runners typically show depth 1-2; sidecars
// and DinD push the parent path deeper.
const deepCgroupNestingThreshold = 4

// CheckRunnerCompat returns runner-compatibility warnings detected from
// the current filesystem. Empty slice means no issues. Safe to call from
// any goroutine; reads /sys/fs/cgroup, /.dockerenv, and /proc/1/cgroup.
func CheckRunnerCompat() []telemetry.CompatWarning {
	return checkRunnerCompatAt(compatPaths{
		cgroupRoot:    "/sys/fs/cgroup",
		dockerenv:     "/.dockerenv",
		init1CgroupFn: readProc1Cgroup,
	})
}

// compatPaths is the set of filesystem inputs the check reads. Split out
// so tests can inject fake paths and synthetic /proc/1/cgroup content.
type compatPaths struct {
	cgroupRoot    string
	dockerenv     string
	init1CgroupFn func() (string, error)
}

func checkRunnerCompatAt(p compatPaths) []telemetry.CompatWarning {
	var warnings []telemetry.CompatWarning

	if !isCgroupV2(p.cgroupRoot) {
		warnings = append(warnings, telemetry.CompatWarning{
			Code:   CompatCodeCgroupV1Detected,
			Detail: fmt.Sprintf("%s is not a cgroup2 mount; defend-mode cgroup BPF hooks require cgroup v2", p.cgroupRoot),
		})
	}

	if _, err := os.Stat(p.dockerenv); err == nil {
		// Inside a container: if the host shares its cgroup namespace
		// (non-delegated), /proc/1/cgroup shows host-side prefix
		// segments (e.g. `/docker/<id>/...`) rather than `/` for the
		// unified hierarchy. A delegated namespace flattens it.
		content, err := p.init1CgroupFn()
		if err != nil {
			warnings = append(warnings, telemetry.CompatWarning{
				Code:   CompatCodeContainerCgroupDetection,
				Detail: fmt.Sprintf("running inside a container but /proc/1/cgroup could not be read: %v", err),
			})
		} else if !cgroupNamespaceDelegated(content) {
			warnings = append(warnings, telemetry.CompatWarning{
				Code:   CompatCodeCgroupNamespaceNonDeleg,
				Detail: "container shares host cgroup namespace; defend-mode cgroup attach may attach to host cgroup root",
			})
		}
	}

	depth, dErr := init1CgroupMaxDepth(p.init1CgroupFn)
	if dErr == nil && depth >= deepCgroupNestingThreshold {
		warnings = append(warnings, telemetry.CompatWarning{
			Code:   CompatCodeDeepCgroupNesting,
			Detail: fmt.Sprintf("/proc/1/cgroup path depth=%d; nested runners can shift cgroup attach points and reduce defend coverage", depth),
		})
	}

	return warnings
}

func isCgroupV2(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	// CGROUP2_SUPER_MAGIC = 0x63677270 ("cgrp").
	const cgroup2Magic = 0x63677270
	return int64(st.Type) == int64(cgroup2Magic)
}

// cgroupNamespaceDelegated returns true when /proc/1/cgroup contents indicate
// the container's cgroup namespace is delegated (paths reduce to "/" or a
// short scope name). Returns false when paths reveal host-side prefixes such
// as "/docker/...", "/kubepods/...", or "/system.slice/docker-...".
func cgroupNamespaceDelegated(procCgroup string) bool {
	for _, line := range strings.Split(procCgroup, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]
		if path == "/" || path == "/init.scope" {
			continue
		}
		lower := strings.ToLower(path)
		if strings.HasPrefix(lower, "/docker/") ||
			strings.HasPrefix(lower, "/kubepods/") ||
			strings.HasPrefix(lower, "/system.slice/docker-") ||
			strings.HasPrefix(lower, "/lxc/") ||
			strings.HasPrefix(lower, "/podman/") {
			return false
		}
	}
	return true
}

// init1CgroupMaxDepth returns the maximum segment depth observed across all
// /proc/1/cgroup lines, e.g. "/foo/bar/baz" → 3. Used to flag nested-runner
// environments where defend cgroup attach lands far from the actual workload.
func init1CgroupMaxDepth(readFn func() (string, error)) (int, error) {
	content, err := readFn()
	if err != nil {
		return 0, err
	}
	maxDepth := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]
		depth := strings.Count(strings.TrimSuffix(path, "/"), "/")
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	return maxDepth, nil
}

func readProc1Cgroup() (string, error) {
	f, err := os.Open("/proc/1/cgroup")
	if err != nil {
		return "", err
	}
	defer f.Close()
	var sb strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return sb.String(), nil
}
