//go:build linux

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AttachPath returns the cgroup directory used for BPF cgroup attach (e.g. link.AttachCgroup).
//
// If override is non-empty (COLDSTEP_CGROUP_PATH), it must exist and be a directory; that
// path is used as-is (useful for self-hosted runners that want to scope to a job cgroup).
//
// Otherwise the cgroup v2 unified-hierarchy root "/sys/fs/cgroup" is returned. Using the
// root is intentional: coldstep runs as root (sudo -E) and must cover ALL job-step
// processes, which on GitHub-hosted ubuntu-latest runners may be placed in sibling or
// parent cgroups relative to the coldstep agent process. Attaching to a sub-cgroup (derived
// from /proc/self/cgroup) would leave those steps unprotected.
//
// cgroup v1 note: "/sys/fs/cgroup" on a v1 host is the tmpfs root, not a cgroup directory,
// so link.AttachCgroup will fail with EINVAL. v1 runners are out of scope; coldstep targets
// GitHub-hosted ubuntu-latest which uses cgroup v2 unified hierarchy (kernel 5.15+).
func AttachPath(override string) (string, error) {
	o := strings.TrimSpace(override)
	if o != "" {
		st, err := os.Stat(o)
		if err != nil {
			return "", fmt.Errorf("cgroup attach path %q: %w", o, err)
		}
		if !st.IsDir() {
			return "", fmt.Errorf("cgroup attach path %q must be a directory", o)
		}
		return filepath.Abs(o)
	}

	return "/sys/fs/cgroup", nil
}
