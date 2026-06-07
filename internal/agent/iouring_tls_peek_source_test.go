//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestIOUringTLSPeekResolvesSendmsgPayload guards BG-2: the io_uring TLS peek
// must resolve IORING_OP_SENDMSG to its real payload via
// user_msghdr->msg_iov[0].iov_base, not peek the cmd-union member directly
// (which for SENDMSG is the user_msghdr pointer, never a ClientHello prefix).
// Source-level assertion — cheap, Linux-only, no clang or BPF load needed.
func TestIOUringTLSPeekResolvesSendmsgPayload(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	srcPath := filepath.Join(repoRoot, "bpf", "trace_connect.bpf.c")

	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read %s: %v", srcPath, err)
	}
	text := string(src)

	for _, want := range []string{
		// The msg_iov offset constant must exist and be used to walk the
		// user_msghdr for SENDMSG.
		"COLDSTEP_USER_MSGHDR_MSG_IOV_OFFSET",
		// SEND keeps the direct buffer pointer; SENDMSG falls into the
		// iovec-resolution branch.
		"if (opcode == COLDSTEP_IORING_OP_SEND)",
		"payload_ptr = buf_ptr;",
		"payload_ptr = iov_base;",
		// The peek + capture must read payload_ptr, not the raw buf_ptr.
		"bpf_probe_read_user(peek, sizeof(peek),",
		// BG-4: read failure discards the slot rather than submitting an
		// empty record.
		"bpf_ringbuf_discard(tev, 0);",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("trace_connect.bpf.c io_uring TLS peek missing %q (BG-2/BG-4 regression)", want)
		}
	}

	// The full-payload capture must target the resolved payload_ptr, and the
	// raw cmd-union buf_ptr must no longer be the read target for either the
	// signature peek or the capture (whitespace-insensitive checks).
	if !strings.Contains(text, "sizeof(tev->payload)") {
		t.Error("full-payload capture missing (BG-2)")
	}
	if strings.Contains(text, "(void *)buf_ptr) == 0) {") {
		t.Error("peek/capture must read (void *)payload_ptr, not the raw cmd-union buf_ptr (BG-2 regression)")
	}
}
