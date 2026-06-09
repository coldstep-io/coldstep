//go:build linux

package actioncli

import (
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestWaitForReady_ChildExit: when the agent pid is already dead and no
// healthy status file exists, waitForReady must return "child_exit" rather
// than spinning until the timeout. Uses a real process run to completion so
// its reaped pid is reliably not-alive.
func TestWaitForReady_ChildExit(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot run /usr/bin/true: %v", err)
	}
	deadPid := cmd.Process.Pid // reaped by Run -> Signal(0) yields ESRCH

	if pidAlive(deadPid) {
		t.Skipf("reaped pid %d still reported alive; environment cannot exercise child_exit", deadPid)
	}

	missing := filepath.Join(t.TempDir(), "never-written.json")
	if got := waitForReady(missing, 5*time.Second, deadPid); got != "child_exit" {
		t.Fatalf("waitForReady with dead pid = %q, want child_exit", got)
	}
}
