//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLSMSendmsgExplicitDestinationUsesUserReadHelper(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	sourcePath := filepath.Join(repoRoot, "bpf", "trace_lsm_defend.bpf.c")

	src, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}

	text := string(src)
	funcStart := strings.Index(text, "int BPF_PROG(lsm_socket_sendmsg")
	if funcStart < 0 {
		t.Fatalf("lsm_socket_sendmsg not found in %s", sourcePath)
	}
	funcText := text[funcStart:]

	branchStart := strings.Index(funcText, "if (address && namelen >= (int)sizeof(struct sockaddr_in)) {")
	if branchStart < 0 {
		t.Fatal("explicit destination branch not found")
	}
	branchText, err := extractBraceDelimitedBlock(funcText[branchStart:])
	if err != nil {
		t.Fatalf("extract explicit destination branch: %v", err)
	}

	if !strings.Contains(branchText, "read_ipv4_sockaddr((unsigned long)address, &dport, &daddr)") {
		t.Fatal("expected explicit destination branch to use read_ipv4_sockaddr")
	}
	if strings.Contains(branchText, "bpf_probe_read_kernel(&daddr") || strings.Contains(branchText, "bpf_probe_read_kernel(&dport") {
		t.Fatal("explicit destination branch must not directly kernel-read sockaddr fields")
	}
}

func extractBraceDelimitedBlock(text string) (string, error) {
	open := strings.IndexByte(text, '{')
	if open < 0 {
		return "", os.ErrInvalid
	}

	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[:i+1], nil
			}
		}
	}
	return "", os.ErrInvalid
}

func TestDefendBackendFallsBackToCgroupWhenLSMAttachFails(t *testing.T) {
	outcome := chooseDefendBackend(defendBackendConfig{
		modeDefend: true,
		haveLSM:    true,
	}, errors.New("lsm attach failed"))
	if outcome.backend != "cgroup" {
		t.Fatalf("expected cgroup fallback, got %q", outcome.backend)
	}
}

func TestDefendBackendStaysLSMWhenAttachSucceeds(t *testing.T) {
	outcome := chooseDefendBackend(defendBackendConfig{
		modeDefend: true,
		haveLSM:    true,
	}, nil)
	if outcome.backend != "lsm" {
		t.Fatalf("expected lsm backend, got %q", outcome.backend)
	}
}

func TestDefendBackendUsesCgroupWhenLSMUnavailable(t *testing.T) {
	outcome := chooseDefendBackend(defendBackendConfig{
		modeDefend: true,
		haveLSM:    false,
	}, nil)
	if outcome.backend != "cgroup" {
		t.Fatalf("expected cgroup backend without LSM, got %q", outcome.backend)
	}
}

// Bug #3: downgradeMode flips the mode label after backend choice when the
// post-attach LSM probe finds the hooks silent. It must NOT clobber the
// allowlist counters captured by setModeAndAllowlist — those were populated
// from the actual BPF maps and remain accurate even when LSM is silent.
func TestDefendStateDowngradeModePreservesAllowlistCounters(t *testing.T) {
	state := newDefendState()
	state.setModeAndAllowlist(defendModeLSM, 7, 3)
	state.setIPv6AllowlistSize(2)

	state.downgradeMode(defendModeCgroup)

	snap := state.snapshot()
	if snap.mode != defendModeCgroup {
		t.Errorf("mode = %q; want %q", snap.mode, defendModeCgroup)
	}
	if snap.allowlistSize != 7 {
		t.Errorf("allowlistSize = %d; want 7 (must not be reset by downgrade)", snap.allowlistSize)
	}
	if snap.allowlistIPv6Size != 2 {
		t.Errorf("allowlistIPv6Size = %d; want 2 (must not be reset by downgrade)", snap.allowlistIPv6Size)
	}
}
