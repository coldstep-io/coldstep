//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// findAgentPID walks the /proc descendant chain rooted at sudoPid looking for
// a process whose comm is "coldstep" — the agent we just spawned via `sudo`.
//
// Bug #15: on most PAM stacks sudo forks before exec'ing the target binary,
// so cmd.Process.Pid (sudoPid) is the sudo process, not the agent. Using
// sudoPid for pidAlive polling masks an agent crash because sudo can stay
// alive after its child dies (e.g. waiting on the wait4 syscall). Using
// sudoPid for SIGTERM is also unreliable — sudo does not proxy signals by
// default, so the agent keeps running. Storing the actual agent PID fixes
// both surfaces.
//
// Returns sudoPid if no coldstep descendant appears within the timeout (best-
// effort fallback so the caller never has a zero PID — e.g. on a kernel /
// sudo configuration where the lookup pattern differs). The discovery races
// the sudo fork; the caller passes a short polling budget (~2s) that fits
// inside the broader readiness window.
func findAgentPID(sudoPid int, timeout time.Duration) int {
	if sudoPid <= 0 {
		return sudoPid
	}
	deadline := time.Now().Add(timeout)
	for {
		if pid := walkForAgentComm(sudoPid, "coldstep"); pid > 0 {
			return pid
		}
		if !time.Now().Before(deadline) {
			return sudoPid
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// walkForAgentComm performs a bounded BFS through /proc/<pid>/task/<pid>/children
// rooted at rootPid, returning the first descendant whose /proc/<pid>/comm
// matches wantComm. Returns 0 if no match is found.
func walkForAgentComm(rootPid int, wantComm string) int {
	queue := []int{rootPid}
	seen := map[int]bool{rootPid: true}
	// Bound the walk to avoid pathological /proc state on a shared runner.
	for steps := 0; len(queue) > 0 && steps < 256; steps++ {
		pid := queue[0]
		queue = queue[1:]
		if pid != rootPid && readComm(pid) == wantComm {
			return pid
		}
		for _, child := range readProcChildren(pid) {
			if seen[child] {
				continue
			}
			seen[child] = true
			queue = append(queue, child)
		}
	}
	return 0
}

func readComm(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// readProcChildren returns the union of /proc/<pid>/task/<tid>/children
// across every thread (TID) of pid. A multi-threaded process can fork from
// any thread; the children list lives under the TID that called fork, not
// uniformly under /proc/<pid>/task/<pid>. Single-threaded native programs
// (sudo) populate /proc/<pid>/task/<pid>/children, but the Go-side unit
// tests fork from the Go runtime's worker threads — we must walk every TID
// to find them.
func readProcChildren(pid int) []int {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		// Fallback: try the conventional path. Useful when /proc/<pid>/task
		// is unreadable but /proc/<pid>/task/<pid>/children is.
		return readChildrenFile(pid, pid)
	}
	seen := map[int]struct{}{}
	var out []int
	for _, ent := range entries {
		tid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		for _, child := range readChildrenFile(pid, tid) {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			out = append(out, child)
		}
	}
	return out
}

func readChildrenFile(pid, tid int) []int {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, tid))
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(raw))
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		if v, err := strconv.Atoi(f); err == nil && v > 0 {
			out = append(out, v)
		}
	}
	return out
}
