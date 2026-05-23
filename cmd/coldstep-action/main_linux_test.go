//go:build linux

package main

import (
	"os"
	"testing"
	"time"
)

// On Linux, sending signal 0 to the current process succeeds, so pidAlive(self)
// is true. That lets us exercise the timeout branch of waitForAgentExit
// deterministically. The equivalent behaviour on Windows differs (Signal(0) is
// not a portable liveness probe), so this test stays Linux-only — the
// production path it covers runs only inside the action on GitHub-hosted
// Linux runners.
func TestWaitForAgentExit_ReturnsFalseOnTimeout(t *testing.T) {
	self := os.Getpid()
	start := time.Now()
	ok := waitForAgentExit(self, 150*time.Millisecond, 30*time.Millisecond)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("waitForAgentExit(selfPID) = true; want false (self is alive)")
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("waitForAgentExit returned too early: %s", elapsed)
	}
}
