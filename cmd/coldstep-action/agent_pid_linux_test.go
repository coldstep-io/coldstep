//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// Bug #15: findAgentPID must locate the descendant whose /proc/<pid>/comm
// matches "coldstep" even when there are intermediate processes (mirroring
// the sudo -> agent fork). Use sh -c 'exec sleep ...' to get a child whose
// comm we control; rename the binary by exec'ing under a different argv[0]
// is non-portable, so instead we use a fake comm by symlinking — too much
// machinery for a unit test. Simpler: exercise the fallback path and the
// "no match" walk semantics.

func TestFindAgentPID_FallbackOnNoMatch(t *testing.T) {
	// Spawn a sleep child so the parent has a descendant, but no descendant
	// has comm "coldstep". findAgentPID must return sudoPid (fallback).
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep not available: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	self := os.Getpid()
	start := time.Now()
	got := findAgentPID(self, 200*time.Millisecond)
	elapsed := time.Since(start)
	if got != self {
		t.Fatalf("findAgentPID with no coldstep descendant: got %d want %d (fallback to sudoPid)", got, self)
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("findAgentPID returned too early: %s (expected ~timeout)", elapsed)
	}
}

func TestFindAgentPID_ZeroSudoPidReturnsZero(t *testing.T) {
	if got := findAgentPID(0, 100*time.Millisecond); got != 0 {
		t.Fatalf("findAgentPID(0) = %d, want 0", got)
	}
	if got := findAgentPID(-1, 100*time.Millisecond); got != -1 {
		t.Fatalf("findAgentPID(-1) = %d, want -1", got)
	}
}

func TestWalkForAgentComm_FindsKnownChild(t *testing.T) {
	// Spawn `sleep` directly so the child's comm is stable as "sleep" — no
	// fork-exec race (a shell wrapper like `sh -c "sleep 5"` may exec into
	// sleep, briefly making comm transition from "sh" to "sleep" and
	// breaking deterministic comparison).
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep not available: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	// Poll briefly for the kernel to populate the children list and for the
	// child's comm to become readable. On loaded CI machines the immediate
	// post-Start window can race.
	deadline := time.Now().Add(500 * time.Millisecond)
	for readComm(cmd.Process.Pid) != "sleep" {
		if !time.Now().Before(deadline) {
			t.Skipf("child comm did not stabilise to 'sleep' within 500ms")
		}
		time.Sleep(25 * time.Millisecond)
	}
	got := walkForAgentComm(os.Getpid(), "sleep")
	if got != cmd.Process.Pid {
		t.Fatalf("walkForAgentComm(\"sleep\"): got %d want %d", got, cmd.Process.Pid)
	}
}
