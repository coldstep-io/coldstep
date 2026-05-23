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

func TestWalkForAgentComm_FindsSelfComm(t *testing.T) {
	// readComm(self) returns this test process's comm — typically
	// "coldstep-action.test" (truncated to 15 chars by the kernel). Use it
	// as the wantComm so the walk has something to match. The root pid is
	// 1 (init), and self should be a descendant.
	selfComm := readComm(os.Getpid())
	if selfComm == "" {
		t.Skipf("could not read /proc/self/comm")
	}
	// Walking from init might be slow on busy systems; instead walk from
	// our own pid with a child to find. Spawn a sh process so we have a
	// known descendant.
	cmd := exec.Command("sh", "-c", "sleep 5")
	if err := cmd.Start(); err != nil {
		t.Skipf("sh not available: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	// Give the kernel a moment to populate /proc/<self>/task/<self>/children.
	time.Sleep(50 * time.Millisecond)
	want := readComm(cmd.Process.Pid)
	if want == "" {
		t.Skipf("could not read child comm")
	}
	got := walkForAgentComm(os.Getpid(), want)
	if got != cmd.Process.Pid {
		t.Fatalf("walkForAgentComm(%q): got %d want %d", want, got, cmd.Process.Pid)
	}
}
