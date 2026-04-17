package report

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func TestBuildDetectMarkdown_PolicyRollupIncludesIgnored(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         0,
		TCPTotal:          5,
		UDPTotal:          0,
		HTTPTotal:         0,
		PolicyCounts:      map[string]int{"ignored": 3, "allowed": 2},
		MaxRowsPerSection: 5,
	})
	if !strings.Contains(md, "**Policy rollups**") {
		t.Fatalf("missing policy rollups header:\n%s", md)
	}
	if !strings.Contains(md, "`ignored`=3") {
		t.Fatalf("expected ignored count in rollups, got:\n%s", md)
	}
}

func TestBuildDetectMarkdown_ProcessTreeSection(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_fork", OK: true}},
		ExecTotal:         0,
		ProcForkTotal:     2,
		ProcessTreeLines:  []string{"bash(1) /bin/bash", "└── true(2) /usr/bin/true"},
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(md, "| **proc_fork** | 2 |") {
		t.Fatalf("missing proc_fork KPI:\n%s", md)
	}
	if !strings.Contains(md, "Process tree (recent)") {
		t.Fatalf("missing section title:\n%s", md)
	}
	if !strings.Contains(md, "bash(1)") {
		t.Fatalf("missing tree line:\n%s", md)
	}
}

func TestBuildDetectMarkdown_KPIAndSections(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		ExecTotal: 1, TCPTotal: 2, UDPTotal: 3, HTTPTotal: 4,
		PolicyCounts: map[string]int{"monitor": 9},
		ExecRows:     []ExecDigestRow{{TS: "t", PID: 1, ThreadID: 99, Comm: "sh", Exe: "/bin/sh"}},
		TCPRows: []TCPDigestRow{{
			TS: "t", PID: 1, Comm: "curl", Remote: "`1.2.3.4:443`",
			Notes: "fqdn `x`", Policy: "monitor",
		}},
		UDPRows: []UDPDigestRow{{TS: "t", PID: 1, Comm: "dig", Remote: "`8.8.8.8:53`", DgramLen: 64, Policy: "monitor"}},
		HTTPRows: []HTTPDigestRow{{
			TS: "t", PID: 1, Comm: "curl", Method: "GET", Host: "h", Path: "/",
			Remote: "`1.1.1.1:80`", Policy: "monitor",
		}},
		JSONLPath:         "/tmp/x.jsonl",
		SeqFirst:          1,
		SeqLast:           10,
		MaxRowsPerSection: 5,
	})
	for _, needle := range []string{
		"## Coldstep · detect",
		"Detect-only: observe, do not block.",
		"### KPI", "| **exec** | 1 |", "| **udp** | 3 |", "| **http** | 4 |",
		"UDP sendto", "HTTP/1 cleartext", "Canonical log (JSONL)", "connect(2)",
		"PID (TGID)", "| `99` |", "`sh`", "Executable (BPF-capped)", "`/bin/sh`",
		"IPv4 sendto and sendmsg egress",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_TLSKPIAndSection(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:          []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true}},
		ExecTotal:    0,
		TCPTotal:     1,
		TLSTotal:     1,
		TLSSNIGate:   true,
		PolicyCounts: map[string]int{"monitor": 1},
		TLSRows: []TLSDigestRow{{
			TS: "t", PID: 42, Comm: "curl", SNI: "example.com",
			Remote: "`93.184.216.34:443`", Policy: "monitor",
		}},
		JSONLPath:         "/tmp/x.jsonl",
		SeqFirst:          1,
		SeqLast:           1,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"| **tls** | 1 |",
		"TLS ClientHello / SNI",
		"example.com",
		"TCP / UDP / HTTP / TLS classification",
		"tls_sni=1",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestTruncateExeForDigest(t *testing.T) {
	long := strings.Repeat("a", execExeDigestMaxBytes+20)
	out := TruncateExeForDigest(long)
	if len(out) > execExeDigestMaxBytes {
		t.Fatalf("len %d > %d", len(out), execExeDigestMaxBytes)
	}
	if !utf8.ValidString(out) {
		t.Fatalf("invalid utf-8")
	}
}

func TestTruncateUTF8ToMaxBytes(t *testing.T) {
	s := "hello" + string([]byte{0xe2, 0x82, 0xac}) + "tail" // euro in middle
	// Cut through the 3-byte euro; result must be valid UTF-8 and <= max
	out := TruncateUTF8ToMaxBytes(s, 8)
	if !utf8.ValidString(out) {
		t.Fatalf("invalid utf-8: %q", out)
	}
	if len(out) > 8 {
		t.Fatalf("len %d > 8", len(out))
	}
}

func TestTruncateUTF8ToMaxBytes_NonPositiveCap(t *testing.T) {
	if got := TruncateUTF8ToMaxBytes("abc", 0); got != "" {
		t.Fatalf("max=0 got %q want empty", got)
	}
	if got := TruncateUTF8ToMaxBytes("abc", -5); got != "" {
		t.Fatalf("max<0 got %q want empty", got)
	}
}

func TestBuildDetectMarkdown_UDPEmptyReason_Degraded(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		UDPDegradedHook: true,
		UDPReaderErrors: 3,
		UDPTotal:        0,
	})
	if !strings.Contains(md, "| — | — | — | — | — | — | degraded hook |") {
		t.Fatalf("missing degraded UDP empty reason row in:\n%s", md)
	}
}

func TestBuildDetectMarkdown_UDPEmptyReason_ReaderErrors(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		UDPReaderErrors: 2,
		UDPTotal:        0,
	})
	if !strings.Contains(md, "| — | — | — | — | — | — | reader errors (2) |") {
		t.Fatalf("missing reader-error UDP empty reason row in:\n%s", md)
	}
}

func TestBuildDetectMarkdown_UDPEmptyReason_NoEvents(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		UDPTotal: 0,
	})
	if !strings.Contains(md, "| — | — | — | — | — | — | no events |") {
		t.Fatalf("missing no-events UDP empty reason row in:\n%s", md)
	}
}

func TestBuildDetectMarkdown_HTTPEmptyReason_Degraded(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		HTTPDegradedHook: true,
		HTTPReaderErrors: 4,
		HTTPTotal:        0,
	})
	if !strings.Contains(md, "| — | — | — | — | — | — | — | degraded hook |") {
		t.Fatalf("missing degraded HTTP empty reason row in:\n%s", md)
	}
}

func TestBuildDetectMarkdown_HTTPEmptyReason_ReaderErrors(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		HTTPReaderErrors: 5,
		HTTPTotal:        0,
	})
	if !strings.Contains(md, "| — | — | — | — | — | — | — | reader errors (5) |") {
		t.Fatalf("missing reader-error HTTP empty reason row in:\n%s", md)
	}
}

func TestBuildDetectMarkdown_HTTPEmptyReason_NoEvents(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		HTTPTotal: 0,
	})
	if !strings.Contains(md, "| — | — | — | — | — | — | — | no events |") {
		t.Fatalf("missing no-events HTTP empty reason row in:\n%s", md)
	}
}

func TestBuildDetectMarkdown_ReasonFlagsIgnoredWhenRowsPresent(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		UDPDegradedHook:  true,
		UDPReaderErrors:  9,
		HTTPDegradedHook: true,
		HTTPReaderErrors: 7,
		UDPRows: []UDPDigestRow{{
			TS: "t", PID: 11, Comm: "dig", Remote: "`8.8.8.8:53`", DgramLen: 64, Policy: "monitor",
		}},
		HTTPRows: []HTTPDigestRow{{
			TS: "t", PID: 12, Comm: "curl", Method: "GET", Host: "example.com", Path: "/",
			Remote: "`1.1.1.1:80`", Policy: "monitor",
		}},
	})
	for _, unexpected := range []string{"| — | — | — | — | — | — | degraded hook |", "| — | — | — | — | — | — | — | degraded hook |"} {
		if strings.Contains(md, unexpected) {
			t.Fatalf("unexpected empty-state reason row when rows are present:\n%s", md)
		}
	}
	if !strings.Contains(md, "8.8.8.8:53") || !strings.Contains(md, "`GET`") {
		t.Fatalf("expected populated UDP/HTTP rows in:\n%s", md)
	}
}

func TestBuildDetectMarkdown_EnforcementSection(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		EnforcementMode:          "enforce",
		EnforcementAllowlistSize: 3,
		EnforcementDenyCount:     2,
		EnforcementFirstDeny: &DenyDigestRow{
			TS:       "2026-01-01T00:00:00Z",
			PID:      1234,
			Comm:     "curl",
			Protocol: "tcp",
			Dst:      "93.184.216.34",
			Dport:    443,
			Reason:   "dst_not_allowlisted",
		},
	})
	for _, needle := range []string{
		"## Coldstep · enforce",
		"Enforce mode: cgroup-scoped IPv4 egress is allowlisted",
		"### Enforcement",
		"| Mode | `enforce` |",
		"| Allowlist size | 3 |",
		"| Deny count | 2 |",
		"First deny",
		"2026-01-01T00:00:00Z",
		"`1234`",
		"`curl`",
		"`tcp`",
		"`93.184.216.34:443`",
		"`dst_not_allowlisted`",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
	if strings.Contains(md, "Detect-only: observe, do not block.") {
		t.Fatalf("enforce digest should not use detect-only banner:\n%s", md)
	}
}

func TestBuildDetectMarkdown_FSKPIAndSection(t *testing.T) {
	t.Parallel()
	in := DigestInput{
		FSGate:  true,
		FSTotal: 3,
		FSRows: []FSDigestRow{
			{TS: "2026-01-01T00:00:00Z", PID: 100, Comm: "bash", Op: "create", Path: "/tmp/foo.txt"},
		},
	}
	md := BuildDetectMarkdown(in)
	for _, want := range []string{"**fs_event**", "Filesystem (recent)", "create", "/tmp/foo.txt"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in digest", want)
		}
	}
}

func TestBuildDetectMarkdown_FSEmptyState_NoEvents(t *testing.T) {
	t.Parallel()
	in := DigestInput{FSGate: true, FSTotal: 0}
	md := BuildDetectMarkdown(in)
	if !strings.Contains(md, "Filesystem (recent)") {
		t.Error("missing FS section header")
	}
	if !strings.Contains(md, "no events") {
		t.Error("missing no-events empty state")
	}
}

func TestBuildDetectMarkdown_FSEmptyState_Degraded(t *testing.T) {
	t.Parallel()
	in := DigestInput{FSGate: true, FSTotal: 0, FSDegradedHook: true}
	md := BuildDetectMarkdown(in)
	if !strings.Contains(md, "degraded hook") {
		t.Error("missing degraded hook empty state")
	}
}

func TestBuildDetectMarkdown_FSEmptyState_ReaderErrors(t *testing.T) {
	t.Parallel()
	in := DigestInput{FSGate: true, FSTotal: 0, FSReaderErrors: 3}
	md := BuildDetectMarkdown(in)
	if !strings.Contains(md, "reader errors (3)") {
		t.Error("missing reader errors empty state")
	}
}

func TestBuildDetectMarkdown_FSGateOff_NoSection(t *testing.T) {
	t.Parallel()
	in := DigestInput{FSGate: false, FSTotal: 5}
	md := BuildDetectMarkdown(in)
	if strings.Contains(md, "Filesystem") {
		t.Error("fs section should be hidden when gate is off")
	}
}

func TestBuildDetectMarkdown_EnforcementDenyReserveFailures(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		EnforcementMode:                "enforce",
		EnforcementAllowlistSize:       2,
		EnforcementDenyReserveFailures: 5,
	})
	for _, needle := range []string{
		"## Coldstep · enforce",
		"### Enforcement",
		"| Deny ringbuf reserve failures (blocked, no JSONL) | 5 |",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_DroppedEventCounters(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DroppedCounts: map[string]int{
			"udp_decode": 2,
			"http_jsonl": 1,
		},
	})
	for _, needle := range []string{
		"| **dropped events (decode/jsonl)** | 3 |",
		"**Dropped event counters**",
		"`udp_decode`=2",
		"`http_jsonl`=1",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}
