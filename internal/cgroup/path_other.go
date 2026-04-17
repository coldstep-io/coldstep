//go:build !linux

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AttachPath returns the cgroup directory used for BPF cgroup attach.
// On non-Linux builds this is only used by config parsing tests; enforcement runs on Linux only.
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
