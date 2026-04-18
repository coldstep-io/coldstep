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
