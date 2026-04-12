//go:build !linux

package agent

import "fmt"

func Main() error {
	return fmt.Errorf("coldstep is supported only on GitHub-hosted ubuntu-latest (amd64) with BPF; build is not linux")
}
