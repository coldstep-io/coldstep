package report

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func TestBuildDetectMarkdown_DetectProfileKPI(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{DetectProfile: "enhanced", ExecTotal: 1, TCPTotal: 1})
	if !strings.Contains(md, "**detect profile**") || !strings.Contains(md, "enhanced") {
		t.Fatalf("expected enhanced detect profile KPI row; got:\n%s", md)
	}
	mdStd := BuildDetectMarkdown(DigestInput{DetectProfile: "standard", ExecTotal: 1})
	if !strings.Contains(mdStd, "| **detect profile** | standard |") {
		t.Fatalf("expected standard detect profile KPI row")
	}
}

func TestBuildDetectMarkdown_TriageRibbon_Detect(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		TCPTotal:          1,
		DroppedCounts:     map[string]int{"decode": 2},
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{"### Triage", "**Mode**", "`detect`", "**JSONL decode drops**", "**2**"} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_TriageRibbon_DefendDeny(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:        "defend",
		DefendDenyCount:   3,
		BPF:               []telemetry.BPFStatus{{Name: "connect", OK: true}},
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(md, "**deny events:** 3") {
		t.Fatalf("missing deny triage:\n%s", md)
	}
}

func TestBuildDetectMarkdown_TriageRibbon_TruthfulnessInterpretation(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:                  []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		ExecTotal:            1,
		TCPTotal:             1,
		SendfileObserved:     2,
		SpliceObserved:       1,
		SendmmsgFirstOnly:    3,
		IoUringSetupObserved: 1,
		MaxRowsPerSection:    50,
	})
	for _, needle := range []string{
		"| **Observability (partial / bypass-class)** |",
		"counter-only",
		"io_uring_setup(2) observed",
		"⚠️ io_uring_setup (syscall-hook bypass class)=1",
		"sendfile partial-observe=2",
		"splice partial-observe=1",
		"sendmmsg first-message-only=3",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_TopDestinations(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		TCPRows: []TCPDigestRow{{
			TS: "t", PID: 1, Comm: "curl", Remote: "`10.0.0.1:443`", Policy: "monitor",
		}},
		HTTPRows: []HTTPDigestRow{{
			TS: "t", PID: 1, Comm: "curl", Method: "GET", Host: "registry.npmjs.org",
			Path: "/", Remote: "`104.16.0.0:443`", Policy: "monitor",
		}},
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{"### Top destinations", "registry.npmjs.org", "10.0.0.1:443", "tcp", "http"} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_TopDestinations_HiddenWhenEmpty(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "exec", OK: true}},
		ExecTotal:         3,
		MaxRowsPerSection: 50,
	})
	if strings.Contains(md, "### Top destinations") {
		t.Fatalf("Top destinations should be hidden when no egress rows present:\n%s", md)
	}
}

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

func TestBuildDetectMarkdown_HeaderAndCompactKPI(t *testing.T) {
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
		"## ✅ coldstep — detect",
		"| exec | tcp | udp | http | tls |",
		"| 1 | 2 | 3 | 4 | — |",
		"<details>",
		"<summary>Technical details",
		"#### Full KPI",
		"| **exec** | 1 |", "| **udp** | 3 |", "| **http** | 4 |",
		"UDP sendto", "HTTP/1 cleartext", "Canonical log (JSONL)", "connect(2)",
		"PID (TGID)", "| `99` |", "`sh`", "Executable (BPF-capped)", "`/bin/sh`",
		"**UDP KPI**",
		"> Full event log: `/tmp/x.jsonl`",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_HeaderEmojiVerdicts(t *testing.T) {
	clean := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
		ExecTotal: 1,
	})
	if !strings.Contains(clean, "## ✅ coldstep — detect") {
		t.Fatalf("clean-run header missing ✅:\n%s", clean)
	}

	review := BuildDetectMarkdown(DigestInput{
		BPF:                       []telemetry.BPFStatus{{Name: "exec", OK: true}},
		UDPRingbufReserveFailures: 1,
	})
	if !strings.Contains(review, "## ⚠️ coldstep — detect") {
		t.Fatalf("review-state header missing ⚠️:\n%s", review)
	}

	alert := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{{Name: "exec", OK: false}},
	})
	if !strings.Contains(alert, "## 🚨 coldstep — detect") {
		t.Fatalf("alert-state header missing 🚨:\n%s", alert)
	}
}

func TestBuildDetectMarkdown_NoForbiddenGFMTags(t *testing.T) {
	// Job Summaries render GFM; <font>, <p align>, <sub>, <center> are not in
	// the allowlist and would appear as literal text. This guards against
	// regression that might re-introduce them.
	inputs := []DigestInput{
		{},
		{ExecTotal: 1, TCPTotal: 1, BPF: []telemetry.BPFStatus{{Name: "x", OK: true}}},
		{
			DefendMode: "defend", DefendDenyCount: 1, DefendAllowlistSize: 1,
			BPF: []telemetry.BPFStatus{{Name: "x", OK: true}},
		},
		{
			BPFMapIntegrityFailures: 2,
			BPF:                     []telemetry.BPFStatus{{Name: "x", OK: false}},
		},
	}
	forbidden := []string{"<font", "<p align", "<sub>", "</sub>", "<center"}
	for i, in := range inputs {
		md := BuildDetectMarkdown(in)
		for _, tag := range forbidden {
			if strings.Contains(md, tag) {
				t.Fatalf("case %d: forbidden tag %q present in digest:\n%s", i, tag, md)
			}
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

func TestBuildDetectMarkdown_TLSConfidenceKPIRow(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:                  []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true}},
		TLSTotal:             3,
		TLSConfidenceFull:    2,
		TLSConfidencePartial: 1,
		TLSConfidenceUnknown: 0,
		TLSSNIGate:           true,
		PolicyCounts:         map[string]int{"monitor": 3},
		MaxRowsPerSection:    50,
	})
	for _, needle := range []string{
		"| **tls SNI confidence** |",
		"full=2",
		"partial=1",
		"unknown=0",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_TLSConfidenceRowHiddenWhenNoTLS(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true}},
		TLSTotal:          0,
		TLSSNIGate:        true,
		MaxRowsPerSection: 50,
	})
	if strings.Contains(md, "tls SNI confidence") {
		t.Fatalf("confidence row should be hidden when TLSTotal=0, got:\n%s", md)
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

func TestBuildDetectMarkdown_DefendPlusLabelBlocking(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:          "defend+cgroup",
		DefendAllowlistSize: 1,
		DefendDenyCount:     4,
		MaxRowsPerSection:   50,
	})
	for _, needle := range []string{
		"coldstep — defend",
		"| **Mode** | `defend`",
		"**deny events:** 4",
		"#### Defend",
		"| Mode | `defend+cgroup` |",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_DefendSection(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:          "defend",
		DefendAllowlistSize: 3,
		DefendDenyCount:     2,
		DefendFirstDeny: &DenyDigestRow{
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
		"coldstep — defend",
		"#### Defend",
		"| Mode | `defend` |",
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
	// The previous design had a Detect-only banner; the new compact header drops it.
	// Defend digests must still announce the mode in the header.
	if strings.Contains(md, "coldstep — detect") {
		t.Fatalf("defend digest should not announce detect mode:\n%s", md)
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

func TestBuildDetectMarkdown_DefendDenyReserveFailures(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:                "defend",
		DefendAllowlistSize:       2,
		DefendDenyReserveFailures: 5,
	})
	for _, needle := range []string{
		"coldstep — defend",
		"#### Defend",
		"| Deny ringbuf reserve failures (blocked, no JSONL) | 5 |",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestTotalDetectRingbufReserveFailures_MatchesTelemetrySum(t *testing.T) {
	t.Parallel()
	in := DigestInput{
		UDPRingbufReserveFailures:      1,
		DNSRingbufReserveFailures:      2,
		ConnectRingbufReserveFailures:  3,
		HTTPRingbufReserveFailures:     4,
		TLSRingbufReserveFailures:      5,
		ExecRingbufReserveFailures:     6,
		ForkRingbufReserveFailures:     7,
		FSRingbufReserveFailures:       8,
		BPFAuditRingbufReserveFailures: 9,
	}
	want := telemetry.SumRingbufReserveFailuresDetectPath(
		in.UDPRingbufReserveFailures,
		in.DNSRingbufReserveFailures,
		in.ConnectRingbufReserveFailures,
		in.HTTPRingbufReserveFailures,
		in.TLSRingbufReserveFailures,
		in.ExecRingbufReserveFailures,
		in.ForkRingbufReserveFailures,
		in.FSRingbufReserveFailures,
		in.BPFAuditRingbufReserveFailures,
	)
	if got := totalDetectRingbufReserveFailures(in); got != want {
		t.Fatalf("digest total %d != telemetry sum %d", got, want)
	}
}

func TestBuildDetectMarkdown_RingbufReserveRollup(t *testing.T) {
	t.Parallel()
	md := BuildDetectMarkdown(DigestInput{
		UDPRingbufReserveFailures:     1,
		ConnectRingbufReserveFailures: 2,
		HTTPRingbufReserveFailures:    3,
	})
	for _, needle := range []string{
		"Ringbuf reserve pressure (total)** | **6**",
		"connect ringbuf reserve=2",
		"http ringbuf reserve=3",
		"udp ringbuf reserve=1",
		"**connect_events ringbuf reserve failures** | 2 |",
		"**http_events ringbuf reserve failures** | 3 |",
		"**udp_events ringbuf reserve failures** | 1 |",
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

func TestBuildDetectMarkdown_CoverageScopeBlock_AlwaysPresent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		in         DigestInput
		ipv6Cell   string
		extraCells []string
	}{
		{"clean detect", DigestInput{
			BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
			ExecTotal: 1,
		}, "IPv6 observed (detect — no enforcement)", nil},
		{"defend gated", DigestInput{
			DefendMode:              "defend",
			DefendAllowlistSize:     1,
			DefendIPv6AllowlistSize: 2,
			DefendDenyCount:         0,
			BPF:                     []telemetry.BPFStatus{{Name: "connect", OK: true}},
		}, "IPv6 gated (defend allowed_ipv6 active)", nil},
		{"defend block-all", DigestInput{
			DefendMode:              "defend",
			DefendAllowlistSize:     1,
			DefendIPv6AllowlistSize: 0,
			DefendDenyCount:         0,
			BPF:                     []telemetry.BPFStatus{{Name: "connect", OK: true}},
		}, "IPv6 denied (defend block-all — empty allowed_ipv6)", nil},
	}
	for _, c := range cases {
		md := BuildDetectMarkdown(c.in)
		needles := []string{
			"**Coverage this run:**",
			"IPv4 TCP/UDP ✓ observed",
			c.ipv6Cell,
			"QUIC/HTTP3 ✗ not observed",
			"Payloads beyond iov[0]: ✓ observed",
		}
		needles = append(needles, c.extraCells...)
		for _, needle := range needles {
			if !strings.Contains(md, needle) {
				t.Fatalf("[%s] missing %q in digest:\n%s", c.name, needle, md)
			}
		}
	}
}

func TestBuildDetectMarkdown_CoverageScopeBlock_PartialWhenSendmmsgFirstOnly(t *testing.T) {
	t.Parallel()
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		SendmmsgFirstOnly: 2,
	})
	for _, needle := range []string{
		"## ⚠️ coldstep — detect",
		"> ⚠️ Partial coverage — see Coverage block below.",
		"Payloads beyond iov[0]: ⚠️ partial",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in digest:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_AllowlistTrust_DefendUnresolved(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:                 "defend",
		UnresolvedAllowlistDomains: []string{"down.example.com", "ipv6-only.example.com"},
		MaxRowsPerSection:          50,
	})
	for _, needle := range []string{
		"### Allowlist trust model",
		"Unresolved allowlist domains",
		"`down.example.com`",
		"`ipv6-only.example.com`",
		"may be blocked",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_RingbufDropKPIRow(t *testing.T) {
	t.Parallel()
	md := BuildDetectMarkdown(DigestInput{
		BPF:                           []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		ConnectRingbufReserveFailures: 4,
		HTTPRingbufReserveFailures:    1,
	})
	for _, needle := range []string{
		"## ⚠️ coldstep — detect",
		"> ⚠️ Partial coverage — see Coverage block below.",
		"| **⚠️ Ringbuf drops (detect-path total)** | 5 events dropped |",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in digest:\n%s", needle, md)
		}
	}
	cleanMD := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		ExecTotal: 1,
	})
	if strings.Contains(cleanMD, "Ringbuf drops (detect-path total)") {
		t.Fatalf("ringbuf drop row should be hidden when no drops; got:\n%s", cleanMD)
	}
}

func TestBuildDetectMarkdown_FooterAlwaysPresent(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{})
	if !strings.Contains(md, "> Full event log:") {
		t.Fatalf("missing footer:\n%s", md)
	}
	if !strings.Contains(md, ".coldstep-events.jsonl") {
		t.Fatalf("footer should default to .coldstep-events.jsonl when path unset:\n%s", md)
	}
}

func TestBuildDetectMarkdown_VisibleLineBudget(t *testing.T) {
	// A typical detect run should produce a compact visible section (above the
	// Technical details fold). Count visible lines until the first <details> at
	// column 0 — that's our budget for what an operator sees by default.
	md := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		ExecTotal: 12, TCPTotal: 4, UDPTotal: 3, HTTPTotal: 0,
		TCPRows: []TCPDigestRow{{
			TS: "t", PID: 1, Comm: "curl", Remote: "`1.2.3.4:443`", Policy: "monitor",
		}},
		MaxRowsPerSection: 50,
	})
	idx := strings.Index(md, "<details>")
	if idx < 0 {
		t.Fatalf("expected Technical details fold; got:\n%s", md)
	}
	visible := md[:idx]
	lines := strings.Count(visible, "\n")
	if lines > 30 {
		t.Fatalf("visible portion is %d lines, budget is 30:\n%s", lines, visible)
	}
}

// TestBuildDetectMarkdown_IPv6Observed_DetectMode covers detect-mode
// rendering: any non-zero IPv6 counter must (a) flip the headline verdict
// to ⚠️ and (b) add a triage row naming detect mode as visibility-only.
// Detect never enforces IPv6 (Phase 2 enforcement is defend-only).
func TestBuildDetectMarkdown_IPv6Observed_DetectMode(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:                 []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:           1,
		IPv6ConnectObserved: 3,
		IPv6SendmsgObserved: 2,
		MaxRowsPerSection:   50,
	})
	for _, needle := range []string{
		"## ⚠️ coldstep — detect",
		"**IPv6 egress detected**",
		"⚠️ **5** non-loopback IPv6 destinations",
		"connect=3 sendmsg=2",
		"detect mode — IPv6 visibility only",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
	if strings.Contains(md, "🚨 coldstep") {
		t.Fatalf("detect mode IPv6 observation must not escalate to 🚨:\n%s", md)
	}
}

// TestBuildDetectMarkdown_IPv6Observed_DefendMode_BlockAll covers Phase 2
// defend-mode with an empty allowed_ipv6 LPM trie: every non-loopback /
// non-link-local IPv6 destination was denied (block-all). The headline
// stays 🚨 because the empty trie likely indicates a missed AAAA config,
// and the triage row tells the operator how to fix it.
func TestBuildDetectMarkdown_IPv6Observed_DefendMode_BlockAll(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:              "defend",
		BPF:                     []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:               1,
		IPv6ConnectObserved:     1,
		DefendIPv6AllowlistSize: 0,
		MaxRowsPerSection:       50,
	})
	for _, needle := range []string{
		"## 🚨 coldstep — defend",
		"**IPv6 egress detected**",
		"🚨 **1** non-loopback IPv6 destinations",
		"defend has no allowed_ipv6 entries",
		"block-all",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

// TestBuildDetectMarkdown_IPv6Observed_DefendMode_Gated covers Phase 2
// defend-mode with a populated allowed_ipv6 LPM trie: traffic was checked,
// matches were allowed, non-matches were denied. The headline must NOT
// be 🚨 (Phase 2 is doing its job), and the triage row should say "gated".
func TestBuildDetectMarkdown_IPv6Observed_DefendMode_Gated(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:              "defend",
		BPF:                     []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:               1,
		IPv6ConnectObserved:     4,
		IPv6SendmsgObserved:     1,
		DefendIPv6AllowlistSize: 3,
		MaxRowsPerSection:       50,
	})
	for _, needle := range []string{
		"## ✅ coldstep — defend",
		"**IPv6 egress detected**",
		"✅ **5** non-loopback IPv6 destinations",
		"gated by 3-entry allowed_ipv6 LPM trie",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
	if strings.Contains(md, "🚨 coldstep") {
		t.Fatalf("Phase 2 gated defend must not escalate to 🚨:\n%s", md)
	}
}

// TestBuildDetectMarkdown_IPv6Observed_ZeroIsClean confirms the IPv6
// triage row only appears when at least one counter is non-zero — clean
// runs must not surface IPv6 noise.
func TestBuildDetectMarkdown_IPv6Observed_ZeroIsClean(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		MaxRowsPerSection: 50,
	})
	if strings.Contains(md, "**IPv6 egress detected**") {
		t.Fatalf("IPv6 triage row must not appear when counters are zero:\n%s", md)
	}
}

// TestBuildDetectMarkdown_SendpageObserved_DefendMode covers the
// kernel-5.15 sendfile/splice gap closure: in defend mode, a non-zero
// SendpageObserved counter must surface the ✅ gap-closed triage row and
// the matching KPI cell inside Technical details.
func TestBuildDetectMarkdown_SendpageObserved_DefendMode(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:        "defend",
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		SendpageObserved:  7,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"**Sendfile/splice (sock_sendpage)**",
		"✅ **7** events gated by `lsm/socket_sendpage`",
		"lsm/socket_sendpage events gated (sendfile/splice closed)",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

// TestBuildDetectMarkdown_SendpageObserved_DetectMode confirms detect mode
// renders the sendpage counter as informational (ℹ️) — the hook still
// fires for visibility but it does not gate egress when defense is off.
func TestBuildDetectMarkdown_SendpageObserved_DetectMode(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		SendpageObserved:  4,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"**Sendfile/splice (sock_sendpage)**",
		"ℹ️ **4** events observed via `lsm/socket_sendpage`",
		"**lsm/socket_sendpage events (sendfile/splice path)** | 4",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

// TestBuildDetectMarkdown_SendpageObserved_ClosesPayloadGap covers the
// coverage scope cell: when sendfile/splice partial-observe counters
// fired but sendpage_observed > 0, the gap is closed and the cell stays
// "✓ observed". Without sendpage, the cell flips to "⚠️ partial".
func TestBuildDetectMarkdown_SendpageObserved_ClosesPayloadGap(t *testing.T) {
	withSendpage := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		SendfileObserved:  2,
		SpliceObserved:    1,
		SendpageObserved:  3,
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(withSendpage, "Payloads beyond iov[0]: ✓ observed") {
		t.Fatalf("sendpage_observed > 0 must mark payload coverage as ✓ observed:\n%s", withSendpage)
	}
	withoutSendpage := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		SendfileObserved:  2,
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(withoutSendpage, "Payloads beyond iov[0]: ⚠️ partial") {
		t.Fatalf("missing partial-coverage cell when sendpage_observed = 0 and sendfile fired:\n%s", withoutSendpage)
	}
}

// TestBuildDetectMarkdown_SendpageObserved_ZeroIsClean confirms the
// sendpage triage and KPI rows only appear when the counter is non-zero.
func TestBuildDetectMarkdown_SendpageObserved_ZeroIsClean(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		MaxRowsPerSection: 50,
	})
	if strings.Contains(md, "Sendfile/splice (sock_sendpage)") {
		t.Fatalf("sendpage triage row must not appear when counter is zero:\n%s", md)
	}
	if strings.Contains(md, "lsm/socket_sendpage") {
		t.Fatalf("sendpage KPI row must not appear when counter is zero:\n%s", md)
	}
}

func TestBuildDetectMarkdown_AllowlistTrust_UnresolvedSuppressedInDetect(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		UnresolvedAllowlistDomains: []string{"down.example.com"},
		MaxRowsPerSection:          50,
	})
	if strings.Contains(md, "Unresolved allowlist domains") {
		t.Fatalf("detect mode should not surface unresolved warning; got:\n%s", md)
	}
}

func TestBuildDetectMarkdown_AllowlistTrust_WildcardRisk(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		WildcardRiskDomains: []string{"*.s3.amazonaws.com", "*.cloudfront.net"},
		MaxRowsPerSection:   50,
	})
	for _, needle := range []string{
		"### Allowlist trust model",
		"High-risk wildcards",
		"`*.s3.amazonaws.com`",
		"`*.cloudfront.net`",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_AllowlistTrust_AgeInfo(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		AllowlistAgeMinutes: 17.4,
		MaxRowsPerSection:   50,
	})
	if !strings.Contains(md, "ℹ️") || !strings.Contains(md, "17 minutes ago") {
		t.Fatalf("expected age info note; got:\n%s", md)
	}

	mdFresh := BuildDetectMarkdown(DigestInput{
		AllowlistAgeMinutes: 2.0,
		MaxRowsPerSection:   50,
	})
	if strings.Contains(mdFresh, "minutes ago") {
		t.Fatalf("should not surface TTL hint when allowlist is fresh; got:\n%s", mdFresh)
	}
}

func TestBuildDetectMarkdown_AllowlistTrust_HiddenWhenEmpty(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{MaxRowsPerSection: 50})
	if strings.Contains(md, "### Allowlist trust model") {
		t.Fatalf("section should be suppressed when nothing to show; got:\n%s", md)
	}
}

func TestBuildDetectMarkdown_DomainContactCounts_SortedDescending(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DomainContactCounts: map[string]int{
			"api.github.com":                5,
			"registry.npmjs.org":            12,
			"sts.amazonaws.com":             2,
			"objects.githubusercontent.com": 7,
		},
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(md, "Domain contact counts") {
		t.Fatalf("missing Domain contact counts section in:\n%s", md)
	}
	// Highest count must appear before the lower ones.
	npmIdx := strings.Index(md, "registry.npmjs.org")
	githubIdx := strings.Index(md, "objects.githubusercontent.com")
	apiIdx := strings.Index(md, "api.github.com")
	stsIdx := strings.Index(md, "sts.amazonaws.com")
	if npmIdx < 0 || githubIdx < 0 || apiIdx < 0 || stsIdx < 0 {
		t.Fatalf("missing domain rows in:\n%s", md)
	}
	if !(npmIdx < githubIdx && githubIdx < apiIdx && apiIdx < stsIdx) {
		t.Fatalf("expected descending order by count; npm=%d github=%d api=%d sts=%d",
			npmIdx, githubIdx, apiIdx, stsIdx)
	}
}

func TestBuildDetectMarkdown_DomainContactCounts_HiddenWhenEmpty(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{MaxRowsPerSection: 50})
	if strings.Contains(md, "Domain contact counts") {
		t.Fatalf("section should be suppressed when empty; got:\n%s", md)
	}
}
