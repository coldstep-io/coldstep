//go:build linux

package cgroup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AttachPath returns the cgroup directory used for BPF cgroup attach (e.g. link.AttachCgroup).
// If override is non-empty (COLDSTEP_CGROUP_PATH), it must exist and be a directory.
// Otherwise cgroup v2 unified hierarchy is read from /proc/self/cgroup (first "0::" line);
// if missing or unusable, "/sys/fs/cgroup" is returned.
//
// Scope assumption — cgroup v2 ONLY. The "0::" prefix in /proc/self/cgroup is
// the unified-hierarchy marker. cgroup v1 hosts emit per-controller lines like
// `12:cpu:/user.slice/...` which have no "0::" entry, so this function falls
// back to "/sys/fs/cgroup" (which on a v1 host is the tmpfs root containing
// per-controller subdirs, not a cgroup directory) and the BPF
// cgroup/connect4 + cgroup/sendmsg4 attach in trace_enforce.bpf.c will fail
// with EINVAL. Coldstep currently targets GitHub-hosted `ubuntu-latest`
// runners which have used cgroup v2 unified hierarchy since the
// `ubuntu-22.04` image (Linux 5.15+). v1 runner support is out of scope.
// See knowledge/reports/2026-04-18-deep-ebpf-code-review-synthesis.md F-U2-02.
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

	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "/sys/fs/cgroup", nil
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		rel := strings.TrimPrefix(line, "0::")
		rel = strings.TrimSpace(rel)
		base := "/sys/fs/cgroup"
		if rel == "" || rel == "/" {
			return base, nil
		}
		rel = strings.TrimPrefix(rel, "/")
		full := filepath.Join(base, rel)
		if st, err := os.Stat(full); err == nil && st.IsDir() {
			return full, nil
		}
		return base, nil
	}
	return "/sys/fs/cgroup", nil
}
