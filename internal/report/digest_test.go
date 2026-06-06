package report

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func TestBuildDetectMarkdown_TCPHandshakesKernelConfirmedRow(t *testing.T) {
	t.Parallel()
	// With kernel-confirmed state events present, the Full KPI table includes
	// a "TCP handshakes (kernel-confirmed)" row breaking the count into
	// established / refused.
	mdConfirmed := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		TCPTotal:          5,
		TCPStateTotal:     5,
		TCPStateConfirmed: 4,
		TCPStateRefused:   1,
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(mdConfirmed, "**TCP handshakes** (kernel-confirmed) | 4 established / 1 refused |") {
		t.Fatalf("missing kernel-confirmed handshakes row in:\n%s", mdConfirmed)
	}

	// Without state events the row is not emitted.
	mdPlain := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		TCPTotal:          3,
		MaxRowsPerSection: 50,
	})
	if strings.Contains(mdPlain, "kernel-confirmed") {
		t.Fatalf("unexpected kernel-confirmed row when TCPStateTotal=0:\n%s", mdPlain)
	}
	if strings.Contains(mdPlain, "TCP handshakes") {
		t.Fatalf("unexpected TCP handshakes row when TCPStateTotal=0:\n%s", mdPlain)
	}
}

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

// Bug #6: JSONL artifacts written by pre-rename agents carry mode:"enforce"
// instead of "defend". Replaying them through BuildDetectMarkdown must still
// treat the run as blocking — surface the defend triage row, allowlist-trust
// section, and IPv6-defend logic — instead of degrading to detect-mode output.
func TestBuildDetectMarkdown_LegacyEnforceModeTreatedAsDefend(t *testing.T) {
	for _, mode := range []string{"enforce", "Enforce", "enforce+cgroup", "ENFORCE+lsm"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			md := BuildDetectMarkdown(DigestInput{
				DefendMode:        mode,
				DefendDenyCount:   7,
				BPF:               []telemetry.BPFStatus{{Name: "connect", OK: true}},
				MaxRowsPerSection: 50,
			})
			// The defend triage cell ("Mode | `defend`") and the deny-count
			// suffix are produced only when isBlockingDigestMode returns true.
			if !strings.Contains(md, "`defend`") {
				t.Errorf("expected defend-mode triage row for legacy mode %q; output:\n%s", mode, md)
			}
			if !strings.Contains(md, "**deny events:** 7") {
				t.Errorf("expected deny-count suffix for legacy mode %q; output:\n%s", mode, md)
			}
		})
	}
}

// Bug #2: the triage ribbon canonicalizes a legacy mode:"enforce" artifact to
// `defend`, but the Defend details table used to render the raw mode string —
// so one digest carried two different labels (ribbon `defend`, details
// `enforce`). Both sites must now render `defend` for every enforce variant.
func TestBuildDetectMarkdown_DefendDetailsCanonicalizesLegacyEnforce(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"enforce", "defend"},
		{"Enforce", "defend"},
		{"enforce+cgroup", "defend+cgroup"},
		{"ENFORCE+lsm", "defend+lsm"},
	} {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			md := BuildDetectMarkdown(DigestInput{
				DefendMode:          tc.mode,
				DefendDenyCount:     2,
				DefendAllowlistSize: 1,
				BPF:                 []telemetry.BPFStatus{{Name: "connect", OK: true}},
				MaxRowsPerSection:   50,
			})
			// Ribbon: Mode row canonicalizes to `defend`.
			if !strings.Contains(md, "**Mode** | `defend`") {
				t.Errorf("ribbon mode not canonicalized for %q; output:\n%s", tc.mode, md)
			}
			// Details: Defend section Mode cell renders the canonical label.
			detailsCell := "| Mode | `" + tc.want + "` |"
			if !strings.Contains(md, detailsCell) {
				t.Errorf("missing details cell %q for %q; output:\n%s", detailsCell, tc.mode, md)
			}
			// The raw enforce label must not leak through either the ribbon
			// or the details cell (digest body otherwise uses the word
			// "enforcement" descriptively, so check the rendered cells only).
			if strings.Contains(md, "**Mode** | `enforce") {
				t.Errorf("ribbon leaked raw enforce label for %q; output:\n%s", tc.mode, md)
			}
			if strings.Contains(md, "| Mode | `enforce") {
				t.Errorf("details leaked raw enforce label for %q; output:\n%s", tc.mode, md)
			}
		})
	}
}

// Bug #6: also exercise the predicate directly so failures point at the source
// of truth instead of routing through BuildDetectMarkdown.
func TestIsBlockingDigestMode_LegacyEnforceAlias(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"defend", true},
		{"DEFEND", true},
		{"defend+cgroup", true},
		{"defend+lsm", true},
		{"enforce", true},
		{"Enforce", true},
		{"ENFORCE", true},
		{"enforce+cgroup", true},
		{"enforce+lsm", true},
		{"detect", false},
		{"", false},
		{"unknown", false},
		{"defendx", false},
		{"enforcex", false},
	} {
		if got := isBlockingDigestMode(tc.mode); got != tc.want {
			t.Errorf("isBlockingDigestMode(%q) = %v, want %v", tc.mode, got, tc.want)
		}
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

func TestBuildDetectMarkdown_IoUringSendRow(t *testing.T) {
	t.Run("hidden when zero", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			BPF:               []telemetry.BPFStatus{{Name: "io_uring_submit_sqe", OK: true}},
			ExecTotal:         1,
			TCPTotal:          1,
			MaxRowsPerSection: 50,
		})
		if strings.Contains(md, "io_uring writes") {
			t.Fatalf("io_uring writes row should be hidden when total is zero; got:\n%s", md)
		}
	})
	t.Run("visible when non-zero", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			BPF:               []telemetry.BPFStatus{{Name: "io_uring_submit_sqe", OK: true}},
			ExecTotal:         1,
			TCPTotal:          1,
			IoUringSendTotal:  4,
			MaxRowsPerSection: 50,
		})
		for _, needle := range []string{
			"| **io_uring writes** | 4 network sends observed (SNI extraction not possible) |",
			"io_uring writes=4",
		} {
			if !strings.Contains(md, needle) {
				t.Fatalf("missing %q in:\n%s", needle, md)
			}
		}
	})
}

func TestBuildDetectMarkdown_IoUringTLSHelloRow(t *testing.T) {
	t.Run("hidden when zero", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			BPF:               []telemetry.BPFStatus{{Name: "io_uring_submit_sqe", OK: true}},
			ExecTotal:         1,
			TCPTotal:          1,
			IoUringSendTotal:  2,
			MaxRowsPerSection: 50,
		})
		if strings.Contains(md, "io_uring TLS ClientHello") {
			t.Fatalf("TLS ClientHello row should be hidden when count is zero; got:\n%s", md)
		}
	})
	t.Run("visible when non-zero", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			BPF:                     []telemetry.BPFStatus{{Name: "io_uring_submit_sqe", OK: true}},
			ExecTotal:               1,
			TCPTotal:                1,
			IoUringSendTotal:        4,
			IoUringTLSHelloObserved: 2,
			MaxRowsPerSection:       50,
		})
		for _, needle := range []string{
			"| **🚨 io_uring TLS ClientHello prefixes** | 2 submissions matched TLS 1.x record signature (enhanced profile peek) |",
			"🚨 io_uring TLS ClientHello=2",
			"**🚨 io_uring TLS ClientHello** counts SQE submissions whose user-space buffer prefix matched",
		} {
			if !strings.Contains(md, needle) {
				t.Fatalf("missing %q in:\n%s", needle, md)
			}
		}
	})
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

// TestBuildDetectMarkdown_HeadlineBadgeText pins the H1 verdict labels — the
// digest now spells out what each emoji means so operators do not mistake ✅
// for "every byte of egress observed". Each emoji must surface with its
// descriptive blockquote line right under the heading.
func TestBuildDetectMarkdown_HeadlineBadgeText(t *testing.T) {
	t.Parallel()

	clean := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
		ExecTotal: 1,
	})
	if !strings.Contains(clean, "> ✅ **No anomalies detected (IPv4 TCP/UDP in scope)**") {
		t.Fatalf("clean-run badge text missing:\n%s", clean)
	}

	review := BuildDetectMarkdown(DigestInput{
		BPF:                       []telemetry.BPFStatus{{Name: "exec", OK: true}},
		UDPRingbufReserveFailures: 1,
	})
	if !strings.Contains(review, "> ⚠️ **Partial observation or coverage gaps — review required**") {
		t.Fatalf("review-state badge text missing:\n%s", review)
	}

	alert := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{{Name: "exec", OK: false}},
	})
	if !strings.Contains(alert, "> 🚨 **BPF failure or canary pipeline issue**") {
		t.Fatalf("alert-state badge text missing:\n%s", alert)
	}
}

// TestBuildDetectMarkdown_RunnerHasIPv6_DowngradesVerdict covers the H1 IPv6
// gating: a runner with IPv6 connectivity but no IPv6 hooks loaded (today:
// detect mode) downgrades a ✅ run to ⚠️ so the headline reflects the
// partial observation envelope.
func TestBuildDetectMarkdown_RunnerHasIPv6_DowngradesVerdict(t *testing.T) {
	t.Parallel()

	// Detect mode with RunnerHasIPv6 must downgrade to ⚠️.
	withIPv6 := BuildDetectMarkdown(DigestInput{
		BPF:           []telemetry.BPFStatus{{Name: "exec", OK: true}},
		ExecTotal:     1,
		RunnerHasIPv6: true,
	})
	if !strings.Contains(withIPv6, "## ⚠️ coldstep — detect") {
		t.Fatalf("RunnerHasIPv6 + detect should downgrade to ⚠️:\n%s", withIPv6)
	}
	if !strings.Contains(withIPv6, "| IPv6 | ✗ not observed (runner has IPv6 — coverage gap) |") {
		t.Fatalf("IPv6 coverage row should call out the runner-has-IPv6 gap:\n%s", withIPv6)
	}

	// Without RunnerHasIPv6 the same input remains ✅.
	withoutIPv6 := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
		ExecTotal: 1,
	})
	if !strings.Contains(withoutIPv6, "## ✅ coldstep — detect") {
		t.Fatalf("baseline detect run should stay ✅:\n%s", withoutIPv6)
	}

	// Defend mode with RunnerHasIPv6 does NOT downgrade — the IPv6 hooks
	// are loaded under defend regardless of allowed_ipv6 size.
	defend := BuildDetectMarkdown(DigestInput{
		BPF:                 []telemetry.BPFStatus{{Name: "exec", OK: true}},
		DefendMode:          "defend",
		DefendAllowlistSize: 1,
		RunnerHasIPv6:       true,
	})
	if !strings.Contains(defend, "## ✅ coldstep — defend") {
		t.Fatalf("defend mode with IPv6 hooks attached should stay ✅:\n%s", defend)
	}
}

// TestBuildDetectMarkdown_RunnerEnv_DinDBox verifies the H13 ⚠️ DinD warning
// box renders only when RunnerEnv is "dind". "standard", "unknown", and the
// zero value all suppress the box.
func TestBuildDetectMarkdown_RunnerEnv_DinDBox(t *testing.T) {
	t.Parallel()

	const dindLine = "> ⚠️ **Docker-in-Docker detected** — inner container traffic not observed by coldstep."

	dind := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
		ExecTotal: 1,
		RunnerEnv: "dind",
	})
	if !strings.Contains(dind, dindLine) {
		t.Fatalf("RunnerEnv=dind should surface the warning box:\n%s", dind)
	}

	for _, env := range []string{"", "standard", "unknown"} {
		out := BuildDetectMarkdown(DigestInput{
			BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
			ExecTotal: 1,
			RunnerEnv: env,
		})
		if strings.Contains(out, dindLine) {
			t.Fatalf("RunnerEnv=%q must NOT render the DinD warning box:\n%s", env, out)
		}
	}
}

// TestBuildDetectMarkdown_CoverageScopeTable_IoUringRow covers the io_uring
// row in the Coverage scope table: probe loaded → "⚠ partial"; probe absent
// or attach failed → "✗ not loaded". The enhanced profile adds a TLS peek
// note to the partial cell.
func TestBuildDetectMarkdown_CoverageScopeTable_IoUringRow(t *testing.T) {
	t.Parallel()

	loadedStandard := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{
			{Name: "exec", OK: true},
			{Name: "raw_tp/io_uring_submit_sqe", OK: true},
		},
		ExecTotal: 1,
	})
	if !strings.Contains(loadedStandard, "| io_uring (enhanced profile only) | ⚠ partial (SQE submission only) |") {
		t.Fatalf("standard profile + loaded io_uring should be ⚠ partial:\n%s", loadedStandard)
	}

	loadedEnhanced := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{
			{Name: "exec", OK: true},
			{Name: "raw_tp/io_uring_submit_sqe", OK: true},
		},
		DetectProfile: "enhanced",
		ExecTotal:     1,
	})
	if !strings.Contains(loadedEnhanced, "| io_uring (enhanced profile only) | ⚠ partial (SQE submission + TLS ClientHello peek) |") {
		t.Fatalf("enhanced profile + loaded io_uring should call out TLS peek:\n%s", loadedEnhanced)
	}

	failed := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{
			{Name: "exec", OK: true},
			{Name: "raw_tp/io_uring_submit_sqe", OK: false, Detail: "tracepoint not present"},
		},
		ExecTotal: 1,
	})
	if !strings.Contains(failed, "| io_uring (enhanced profile only) | ✗ not loaded |") {
		t.Fatalf("failed io_uring probe should show ✗ not loaded:\n%s", failed)
	}

	absent := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
		ExecTotal: 1,
	})
	if !strings.Contains(absent, "| io_uring (enhanced profile only) | ✗ not loaded |") {
		t.Fatalf("absent io_uring probe should show ✗ not loaded:\n%s", absent)
	}
}

// TestBuildDetectMarkdown_CoverageScopeTable_UnixSocketsAlwaysNotObserved
// pins the Unix sockets row: coldstep has no AF_UNIX probe today, so the
// row is structurally "✗ not observed" on every digest.
func TestBuildDetectMarkdown_CoverageScopeTable_UnixSocketsAlwaysNotObserved(t *testing.T) {
	t.Parallel()
	for _, in := range []DigestInput{
		{},
		{BPF: []telemetry.BPFStatus{{Name: "exec", OK: true}}, ExecTotal: 5},
		{DefendMode: "defend", DefendAllowlistSize: 2, BPF: []telemetry.BPFStatus{{Name: "exec", OK: true}}},
	} {
		md := BuildDetectMarkdown(in)
		if !strings.Contains(md, "| Unix sockets | ✗ not observed |") {
			t.Fatalf("missing Unix sockets coverage row in:\n%s", md)
		}
	}
}

// TestBuildDetectMarkdown_CoverageScopeTable_QUICRowFlipsOnCandidate verifies
// the QUIC row pivots from "✗ not observed" to a ⚠ cell when port-443 UDP
// candidates fired this run — the payload is still encrypted, but the row
// must signal that flows fell into the gap.
func TestBuildDetectMarkdown_CoverageScopeTable_QUICRowFlipsOnCandidate(t *testing.T) {
	t.Parallel()
	withQUIC := BuildDetectMarkdown(DigestInput{
		BPF:                []telemetry.BPFStatus{{Name: "exec", OK: true}},
		QUICCandidateCount: 4,
	})
	if !strings.Contains(withQUIC, "| QUIC / HTTP3 | ⚠ candidates observed (payload encrypted, not inspected) |") {
		t.Fatalf("QUIC candidates should flip the coverage cell to ⚠:\n%s", withQUIC)
	}
	withoutQUIC := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{{Name: "exec", OK: true}},
	})
	if !strings.Contains(withoutQUIC, "| QUIC / HTTP3 | ✗ not observed |") {
		t.Fatalf("default QUIC cell should be ✗ not observed:\n%s", withoutQUIC)
	}
}

// TestBuildDetectMarkdown_CoverageScopeTable_QUICRowH19 locks the H19 cell
// wording when QuicObservedCount is set. QuicObservedCount takes precedence
// over the older QUICCandidateCount predicate so a single run carries the
// heuristic phrasing in both the coverage row and the technical-details
// "possible-quic" note.
func TestBuildDetectMarkdown_CoverageScopeTable_QUICRowH19(t *testing.T) {
	t.Parallel()
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "exec", OK: true}},
		QuicObservedCount: 12,
	})
	for _, needle := range []string{
		"| QUIC / HTTP3 | ⚠️ QUIC/HTTP3 (UDP 443) — 12 events observed (heuristic, not enforced) |",
		"**note: possible-quic**",
		"heuristic only",
		"out of scope",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
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

// TestBuildDetectMarkdown_TLSConfidencePartialDowngradesVerdict pins the H8
// behaviour: any partial- or unknown-tier TLS event must downgrade the
// otherwise-✅ headline to ⚠️ so operators see the trust gap in the verdict
// rather than buried in the KPI table. Gated on TLSTotal > 0; a TLS-free run
// stays ✅ even if the counters are non-zero (cannot happen in practice, but
// the gate keeps the rule self-consistent with TLSConfidenceRowHiddenWhenNoTLS).
func TestBuildDetectMarkdown_TLSConfidencePartialDowngradesVerdict(t *testing.T) {
	t.Parallel()

	// Partial > 0 triggers the downgrade. KPI row must also be present so the
	// ⚠️ headline points to a visible source of doubt in the same digest.
	withPartial := BuildDetectMarkdown(DigestInput{
		BPF:                  []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (tls)", OK: true}},
		TCPTotal:             1,
		TLSTotal:             2,
		TLSConfidenceFull:    1,
		TLSConfidencePartial: 1,
		TLSSNIGate:           true,
		PolicyCounts:         map[string]int{"monitor": 2},
		MaxRowsPerSection:    50,
	})
	if !strings.Contains(withPartial, "## ⚠️ coldstep — detect") {
		t.Fatalf("TLSConfidencePartial > 0 should downgrade verdict to ⚠️; got:\n%s", withPartial)
	}
	for _, needle := range []string{
		"| **tls SNI confidence** |",
		"full=1",
		"partial=1",
	} {
		if !strings.Contains(withPartial, needle) {
			t.Fatalf("missing KPI needle %q in:\n%s", needle, withPartial)
		}
	}

	// Unknown > 0 (no partials) likewise downgrades — both tiers in the
	// numerator are intentional, since unknown means we shipped a TLS row
	// with no usable SNI and an allow/deny decision relied on the lack of
	// signal.
	withUnknown := BuildDetectMarkdown(DigestInput{
		BPF:                  []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (tls)", OK: true}},
		TCPTotal:             1,
		TLSTotal:             1,
		TLSConfidenceUnknown: 1,
		TLSSNIGate:           true,
		PolicyCounts:         map[string]int{"monitor": 1},
		MaxRowsPerSection:    50,
	})
	if !strings.Contains(withUnknown, "## ⚠️ coldstep — detect") {
		t.Fatalf("TLSConfidenceUnknown > 0 should downgrade verdict to ⚠️; got:\n%s", withUnknown)
	}

	// Baseline: full-only counters keep the verdict at ✅. Cross-checks that
	// the downgrade is gated on partial+unknown, not on the mere presence of
	// any TLS event.
	fullOnly := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (tls)", OK: true}},
		TCPTotal:          1,
		TLSTotal:          1,
		TLSConfidenceFull: 1,
		TLSSNIGate:        true,
		PolicyCounts:      map[string]int{"monitor": 1},
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(fullOnly, "## ✅ coldstep — detect") {
		t.Fatalf("full-only TLS confidence should keep ✅ verdict; got:\n%s", fullOnly)
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

func TestBuildDetectMarkdown_KTLSKPIRowHiddenWhenZero(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (ktls)", OK: true}},
		ExecTotal:         0,
		TCPTotal:          0,
		KTLSOffloadTotal:  0,
		PolicyCounts:      map[string]int{},
		MaxRowsPerSection: 50,
	})
	if strings.Contains(md, "KTLS offload") {
		t.Fatalf("KTLS row should be hidden when count is zero:\n%s", md)
	}
}

func TestBuildDetectMarkdown_KTLSKPIRowShownAndNoteRendered(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (ktls)", OK: true}},
		ExecTotal:         0,
		TCPTotal:          3,
		KTLSOffloadTotal:  2,
		PolicyCounts:      map[string]int{"monitor": 3},
		JSONLPath:         "/tmp/x.jsonl",
		SeqFirst:          1,
		SeqLast:           5,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"| **KTLS offload** | 2 sockets · SNI extraction not possible |",
		"setsockopt(SOL_TLS, TLS_TX|TLS_RX)",
		"cannot resolve SNI",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

// TestBuildDetectMarkdown_TLSConfidencePerRowAndLegend exercises the
// per-row Confidence column in the recent-TLS table and the tier-meaning
// legend that lands in the Technical-details fold. Co-existing tiers must
// be rendered with their reason code so operators can attribute KPI counts
// to specific destinations.
func TestBuildDetectMarkdown_TLSConfidencePerRowAndLegend(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:                  []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true}},
		TCPTotal:             1,
		TLSTotal:             3,
		TLSConfidenceFull:    1,
		TLSConfidencePartial: 1,
		TLSConfidenceUnknown: 1,
		TLSSNIGate:           true,
		PolicyCounts:         map[string]int{"monitor": 3},
		TLSRows: []TLSDigestRow{
			{TS: "t1", PID: 10, Comm: "curl", SNI: "a.example", Remote: "`1.1.1.1:443`", Policy: "monitor", Confidence: telemetry.TLSConfidenceFull},
			{TS: "t2", PID: 11, Comm: "curl", SNI: strings.Repeat("a", 255), Remote: "`1.1.1.2:443`", Policy: "monitor", Confidence: telemetry.TLSConfidencePartial},
			{TS: "t3", PID: 12, Comm: "curl", SNI: "", Remote: "`1.1.1.3:443`", Policy: "monitor", Confidence: telemetry.TLSConfidenceUnknown},
		},
		JSONLPath:         "/tmp/x.jsonl",
		SeqFirst:          1,
		SeqLast:           3,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"| Time (UTC) | PID | Comm | SNI | Remote | Policy | Confidence |",
		"`full`",
		"`partial`",
		"`unknown`",
		"complete ClientHello parsed in a single syscall buffer",
		"capture/RFC boundary",
		"inferred from prior DNS / connect correlation",
		"TLS framing detected but no usable SNI signal",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

// TestBuildDetectMarkdown_TLSConfidenceEmptyRowDefault verifies that a
// TLSDigestRow with no Confidence value renders as the reserved "unknown"
// tier so the column is never blank in the recent-TLS table.
func TestBuildDetectMarkdown_TLSConfidenceEmptyRowDefault(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true}},
		TLSTotal:          1,
		TLSSNIGate:        true,
		PolicyCounts:      map[string]int{"monitor": 1},
		TLSRows:           []TLSDigestRow{{TS: "t", PID: 1, Comm: "x", SNI: "n.example", Remote: "`1.1.1.1:443`", Policy: "monitor"}},
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(md, "`unknown`") {
		t.Fatalf("expected zero-value confidence to render as `unknown`, got:\n%s", md)
	}
}

func TestBuildDetectMarkdown_ECHNote_PresentWhenTLSObserved(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, tls)", OK: true}},
		TCPTotal:          1,
		TLSTotal:          1,
		TLSSNIGate:        true,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"**TLS 1.3 Encrypted ClientHello (ECH):**",
		"outer (CDN/proxy) SNI",
		"cloudflare-ech.com",
		"DNS HTTPS records",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_ECHNote_AbsentWhenNoTLS(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		TCPTotal:          1,
		TLSTotal:          0,
		MaxRowsPerSection: 50,
	})
	if strings.Contains(md, "Encrypted ClientHello") {
		t.Fatalf("ECH paragraph should be absent when TLSTotal == 0:\n%s", md)
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

func TestBuildDetectMarkdown_QUICCandidateKPI(t *testing.T) {
	t.Parallel()
	md := BuildDetectMarkdown(DigestInput{
		UDPTotal:           5,
		QUICCandidateCount: 3,
	})
	for _, needle := range []string{
		"| **QUIC (port-443 UDP)** | 3 flows · payload not inspected |",
		"**QUIC (port-443 UDP)** counts UDP egress to non-loopback IPv4 on port 443",
		"Payload content is encrypted",
		"not inspected",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_QUICCandidateKPI_Hidden_WhenZero(t *testing.T) {
	t.Parallel()
	md := BuildDetectMarkdown(DigestInput{
		UDPTotal:           5,
		QUICCandidateCount: 0,
	})
	for _, unexpected := range []string{
		"QUIC (port-443 UDP)",
		"payload not inspected",
	} {
		if strings.Contains(md, unexpected) {
			t.Fatalf("unexpected QUIC row when count=0:\n%s", md)
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
		name     string
		in       DigestInput
		ipv6Cell string
	}{
		{"clean detect", DigestInput{
			BPF:       []telemetry.BPFStatus{{Name: "exec", OK: true}},
			ExecTotal: 1,
		}, "| IPv6 | ✗ not observed |"},
		{"defend gated", DigestInput{
			DefendMode:              "defend",
			DefendAllowlistSize:     1,
			DefendIPv6AllowlistSize: 2,
			DefendDenyCount:         0,
			BPF:                     []telemetry.BPFStatus{{Name: "connect", OK: true}},
		}, "| IPv6 | ✓ gated (defend allowed_ipv6 active) |"},
		{"defend block-all", DigestInput{
			DefendMode:              "defend",
			DefendAllowlistSize:     1,
			DefendIPv6AllowlistSize: 0,
			DefendDenyCount:         0,
			BPF:                     []telemetry.BPFStatus{{Name: "connect", OK: true}},
		}, "| IPv6 | ✓ gated (defend block-all — empty allowed_ipv6) |"},
	}
	for _, c := range cases {
		md := BuildDetectMarkdown(c.in)
		needles := []string{
			"**Coverage scope**",
			"| Traffic class | Status |",
			"| IPv4 TCP | ✓ observed |",
			"| IPv4 UDP (sendmsg) | ✓ observed |",
			c.ipv6Cell,
			"| QUIC / HTTP3 | ✗ not observed |",
			"| io_uring (enhanced profile only) | ✗ not loaded |",
			"| Unix sockets | ✗ not observed |",
			"| Payloads beyond iov[0] | ✓ observed |",
		}
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
		"| Payloads beyond iov[0] | ⚠️ partial |",
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

// TestBuildDetectMarkdown_RingbufDropBadge_PerChannel asserts that every
// detect-path ringbuf reserve failure counter individually flips the headline
// badge to ⚠️. This is the H2 "silent loss must be visible" guarantee: any
// channel losing events on its own is enough to override the otherwise-✅
// verdict, with no other counters required.
func TestBuildDetectMarkdown_RingbufDropBadge_PerChannel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   DigestInput
	}{
		{"connect", DigestInput{ConnectRingbufReserveFailures: 1}},
		{"udp", DigestInput{UDPRingbufReserveFailures: 1}},
		{"dns", DigestInput{DNSRingbufReserveFailures: 1}},
		{"http", DigestInput{HTTPRingbufReserveFailures: 1}},
		{"tls", DigestInput{TLSRingbufReserveFailures: 1}},
		{"exec", DigestInput{ExecRingbufReserveFailures: 1}},
		{"fork", DigestInput{ForkRingbufReserveFailures: 1}},
		{"fs", DigestInput{FSRingbufReserveFailures: 1}},
		{"bpf_audit", DigestInput{BPFAuditRingbufReserveFailures: 1}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := tc.in
			in.BPF = []telemetry.BPFStatus{{Name: "syscalls", OK: true}}
			md := BuildDetectMarkdown(in)
			if !strings.Contains(md, "## ⚠️ coldstep — detect") {
				t.Fatalf("expected ⚠️ header for %s channel; got:\n%s", tc.name, md)
			}
			if !strings.Contains(md, "**⚠️ Dropped events (ringbuf overflow)**") {
				t.Fatalf("expected dropped-events KPI row for %s channel; got:\n%s", tc.name, md)
			}
		})
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
		"| **⚠️ Dropped events (ringbuf overflow)** | 5 |",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in digest:\n%s", needle, md)
		}
	}
	cleanMD := BuildDetectMarkdown(DigestInput{
		BPF:       []telemetry.BPFStatus{{Name: "syscalls", OK: true}},
		ExecTotal: 1,
	})
	if strings.Contains(cleanMD, "Dropped events (ringbuf overflow)") {
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
	// Budget intentionally accommodates the H1 Coverage scope table (≈10 lines)
	// that makes the observation envelope explicit on every digest.
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
	if lines > 40 {
		t.Fatalf("visible portion is %d lines, budget is 40:\n%s", lines, visible)
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

// TestBuildDetectMarkdown_IPv6EventCount_DetectMode covers the H7 path:
// detect mode with the standalone traceipv6 hook fires per-event ringbuf
// records into IPv6EventCount. The headline must downgrade to ⚠️, a
// dedicated `> ⚠️ **IPv6 egress detected (not enforced)** — N connection(s)
// observed` blockquote must render under the verdict, and the triage row +
// KPI table must surface the ringbuf event count (defend-only
// connect/sendmsg counters are zero in this mode).
func TestBuildDetectMarkdown_IPv6EventCount_DetectMode(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{
			{Name: "sched_process_exec", OK: true},
			{Name: "cgroup/connect6+sendmsg6 (ipv6_obs)", OK: true},
		},
		ExecTotal:         1,
		IPv6EventCount:    7,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"## ⚠️ coldstep — detect",
		"> ⚠️ **IPv6 egress detected (not enforced)** — 7 connection(s) observed",
		"**IPv6 egress detected**",
		"⚠️ **7** non-loopback IPv6 destinations",
		"7 ringbuf event(s)",
		"detect mode — IPv6 visibility only",
		"ipv6 egress events (detect — observe-only, IPv4-only enforcement)",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
	if strings.Contains(md, "🚨 coldstep") {
		t.Fatalf("detect mode H7 observation must not escalate to 🚨:\n%s", md)
	}
}

// TestBuildDetectMarkdown_IPv6EventCount_RunnerHasIPv6_NoGapDowngrade covers
// the H1 interaction: a runner that advertises IPv6 connectivity used to
// downgrade detect-mode verdicts to ⚠️ on the grounds that no IPv6 hooks
// were loaded. With the H7 `cgroup/connect6+sendmsg6 (ipv6_obs)` BPF status
// row present and OK, that specific gap closes — only an actual observed
// event or other partial-coverage signal should downgrade.
func TestBuildDetectMarkdown_IPv6EventCount_RunnerHasIPv6_NoGapDowngrade(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF: []telemetry.BPFStatus{
			{Name: "sched_process_exec", OK: true},
			{Name: "cgroup/connect6+sendmsg6 (ipv6_obs)", OK: true},
		},
		ExecTotal:         1,
		RunnerHasIPv6:     true,
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(md, "## ✅ coldstep — detect") {
		t.Fatalf("H7 hook attached should keep ✅ even when runner has IPv6:\n%s", md)
	}
	if !strings.Contains(md, "| IPv6 | ✓ observed (detect — H7 observe-only hook, no events) |") {
		t.Fatalf("Coverage row should report H7 hook attached when no events fired:\n%s", md)
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
	if !strings.Contains(withSendpage, "| Payloads beyond iov[0] | ✓ observed |") {
		t.Fatalf("sendpage_observed > 0 must mark payload coverage as ✓ observed:\n%s", withSendpage)
	}
	withoutSendpage := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		ExecTotal:         1,
		SendfileObserved:  2,
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(withoutSendpage, "| Payloads beyond iov[0] | ⚠️ partial |") {
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
		"High-risk wildcard domains in allowlist",
		"`*.s3.amazonaws.com`",
		"`*.cloudfront.net`",
		"may match unintended hosts",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

func TestBuildDetectMarkdown_AllowlistTrust_StaleWarning(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		AllowlistCompileTime: time.Now().Add(-6 * time.Minute),
		MaxRowsPerSection:    50,
	})
	for _, needle := range []string{
		"⚠️",
		"DNS allowlist may be stale",
		"compiled 6 minutes ago",
		"DNS TTLs may have expired",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in stale warning; got:\n%s", needle, md)
		}
	}

	mdFresh := BuildDetectMarkdown(DigestInput{
		AllowlistCompileTime: time.Now().Add(-2 * time.Minute),
		MaxRowsPerSection:    50,
	})
	if strings.Contains(mdFresh, "may be stale") {
		t.Fatalf("should not surface TTL hint when allowlist is fresh; got:\n%s", mdFresh)
	}

	mdZero := BuildDetectMarkdown(DigestInput{
		MaxRowsPerSection: 50,
	})
	if strings.Contains(mdZero, "may be stale") {
		t.Fatalf("should not surface TTL hint when AllowlistCompileTime is zero; got:\n%s", mdZero)
	}
}

func TestBuildDetectMarkdown_AllowlistTrust_EntryCountNote(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:          "defend",
		AllowlistEntryCount: 42,
		MaxRowsPerSection:   50,
	})
	for _, needle := range []string{
		"### Allowlist trust model",
		"Allowlist: 42 IPv4 entries loaded at startup",
		"fixed until restart",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in entry-count note; got:\n%s", needle, md)
		}
	}

	mdDetect := BuildDetectMarkdown(DigestInput{
		AllowlistEntryCount: 42,
		MaxRowsPerSection:   50,
	})
	if strings.Contains(mdDetect, "IPv4 entries loaded at startup") {
		t.Fatalf("entry-count note must be suppressed in detect mode; got:\n%s", mdDetect)
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

// H10 / DNS-6e: every allowlist domain must appear in the cross-reference
// table under defend mode; entries observed at least once carry their count,
// entries with zero observations carry the trim-candidate note so operators
// can shrink the allowlist between runs.
func TestBuildDetectMarkdown_AllowlistDomainContactSummary(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		DefendMode:       "defend",
		AllowlistDomains: []string{"api.github.com", "registry.npmjs.org", "unused.example.com"},
		DomainContactCounts: map[string]int{
			"api.github.com":     7,
			"registry.npmjs.org": 3,
			// unused.example.com has no contacts; treated as a trim candidate.
		},
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		"### Allowlist trust model",
		"Allowlist domain contact summary",
		"`api.github.com`",
		"`registry.npmjs.org`",
		"`unused.example.com`",
		"no contacts observed — consider removing from allowlist",
		"1 unused entry (trim candidates)",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	}
}

// H10: in detect mode there is no allowlist to enforce against, so the
// cross-reference table must remain hidden even when AllowlistDomains is
// non-empty (defensive — buildDigestInput won't normally populate this list
// outside defend mode, but the renderer is the last line of defence).
func TestBuildDetectMarkdown_AllowlistDomainContactSummary_HiddenInDetect(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		AllowlistDomains:  []string{"api.github.com"},
		MaxRowsPerSection: 50,
	})
	if strings.Contains(md, "Allowlist domain contact summary") {
		t.Fatalf("cross-ref table must be suppressed outside defend mode; got:\n%s", md)
	}
}

// TestBuildDetectMarkdown_KTLSBucket exercises the P4 wiring: a TLSDigestRow
// whose Confidence was forced to unknown by the readTLSRing KTLS override
// (ConfidenceReason="ktls") must surface in three places in the digest:
//  1. The TLS SNI KPI cell gets a `(N ktls-offloaded)` annotation inside the
//     unknown bucket so the headline count splits structural vs parse-failure.
//  2. The per-row Confidence column reads `unknown ⚠ ktls` instead of plain
//     `unknown` so operators can attribute the row to kernel-TLS offload.
//  3. The technical-details fold gains a "KTLS-offloaded sockets" paragraph
//     that points operators at the `ktls_offload` JSONL events for cross-ref.
//
// Gated on TLSConfidenceUnknownKTLS > 0 throughout — the regression that this
// test catches is silently rolling the override into the plain unknown bucket
// and losing the structural-vs-parse-failure signal.
func TestBuildDetectMarkdown_KTLSBucket(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:                      []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true}},
		TCPTotal:                 1,
		TLSTotal:                 1,
		TLSConfidenceFull:        0,
		TLSConfidencePartial:     0,
		TLSConfidenceUnknown:     1,
		TLSConfidenceUnknownKTLS: 1,
		TLSSNIGate:               true,
		PolicyCounts:             map[string]int{"monitor": 1},
		TLSRows: []TLSDigestRow{
			{
				TS: "t1", PID: 4242, Comm: "nginx",
				SNI:              "",
				Remote:           "`10.0.0.1:443`",
				Policy:           "monitor",
				Confidence:       telemetry.TLSConfidenceUnknown,
				ConfidenceReason: "ktls",
			},
		},
		JSONLPath:         "/tmp/x.jsonl",
		SeqFirst:          1,
		SeqLast:           1,
		MaxRowsPerSection: 50,
	})
	for _, needle := range []string{
		// KPI cell — unknown bucket carries the ktls sub-count.
		"unknown=1 (1 ktls-offloaded)",
		// Per-row column — confidence annotated with the ktls reason.
		"`unknown ⚠ ktls`",
		// Technical-details paragraph — explains the structural blind spot.
		"**KTLS-offloaded sockets** (1 detected)",
		"SNI extraction is structurally impossible",
		"`ktls_offload` events in the JSONL",
	} {
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in digest:\n%s", needle, md)
		}
	}
}

// TestBuildDetectMarkdown_KTLSBucketHiddenWhenZero guards against the digest
// surfacing the KTLS annotation/paragraph on runs where no TLS event was
// overridden — the headline KPI cell must read plain `unknown=K` without the
// trailing `(N ktls-offloaded)` parenthetical and the tech-details paragraph
// must stay folded out of the markdown.
func TestBuildDetectMarkdown_KTLSBucketHiddenWhenZero(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:                      []telemetry.BPFStatus{{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true}},
		TLSTotal:                 1,
		TLSConfidenceFull:        1,
		TLSConfidenceUnknown:     0,
		TLSConfidenceUnknownKTLS: 0,
		TLSSNIGate:               true,
		PolicyCounts:             map[string]int{"monitor": 1},
		MaxRowsPerSection:        50,
	})
	if strings.Contains(md, "ktls-offloaded)") {
		t.Fatalf("KPI ktls-offloaded annotation should be hidden when count is zero:\n%s", md)
	}
	if strings.Contains(md, "**KTLS-offloaded sockets**") {
		t.Fatalf("tech-details KTLS paragraph should be hidden when count is zero:\n%s", md)
	}
}

func TestDigest_EgressBackstopRow(t *testing.T) {
	t.Run("hidden when zero", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			BPF:               []telemetry.BPFStatus{{Name: "cgroup_skb/egress", OK: true}},
			ExecTotal:         1,
			TCPTotal:          1,
			MaxRowsPerSection: 50,
		})
		if strings.Contains(md, "egress backstop") {
			t.Fatalf("row must be hidden when zero:\n%s", md)
		}
	})
	t.Run("visible when non-zero", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			BPF:                 []telemetry.BPFStatus{{Name: "cgroup_skb/egress", OK: true}},
			ExecTotal:           1,
			TCPTotal:            1,
			EgressBackstopCount: 4,
			EgressBackstopDsts:  []string{"198.51.100.9", "203.0.113.7"},
			MaxRowsPerSection:   50,
		})
		needle := "| **🚨 egress backstop (bypassed address hooks)** | 4 packet(s) to 2 non-allowlisted IP(s) reached cgroup_skb egress without a connect4/sendmsg4 decision: 198.51.100.9, 203.0.113.7 |"
		if !strings.Contains(md, needle) {
			t.Fatalf("missing %q in:\n%s", needle, md)
		}
	})
}
