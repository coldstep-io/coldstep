//go:build linux

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func TestRun_BuildsDigestInputWithUDPHTTPSectionState(t *testing.T) {
	stats := newRunStats()
	stats.addExec()
	stats.addTCP(policy.ClassAllowed)
	stats.addUDP(policy.ClassMonitor)
	stats.addUDP(policy.ClassMonitor)
	stats.addHTTP(policy.ClassNotListed)
	stats.addDropped("udp_decode")
	stats.addDropped("udp_decode")
	stats.addDropped("http_jsonl")

	state := newNetworkSectionState()
	state.addUDPReaderError()
	state.addUDPDecodeError()
	state.addHTTPReaderError()
	state.addHTTPDecodeError()
	state.addHTTPDecodeError()

	in := buildDigestInput(
		stats,
		[]telemetry.BPFStatus{
			{Name: "sched_process_exec", OK: true},
			{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: "disabled"},
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		".coldstep-events.jsonl",
		4,
		120,
		state.snapshot(),
		enforcementSnapshot{},
		nil,
		false,
		forkSectionSnapshot{},
		false,
		false,
		nil,
		fsSectionSnapshot{},
		false,
	)

	if !in.UDPDegradedHook {
		t.Fatal("expected UDPDegradedHook=true when raw_tp hook is degraded")
	}
	if !in.HTTPDegradedHook {
		t.Fatal("expected HTTPDegradedHook=true when raw_tp hook is degraded")
	}
	if !in.TLSDegradedHook {
		t.Fatal("expected TLSDegradedHook=true when raw_tp hook is degraded")
	}
	if in.UDPReaderErrors != 2 {
		t.Fatalf("UDPReaderErrors=%d want 2 (reader+decode)", in.UDPReaderErrors)
	}
	if in.HTTPReaderErrors != 3 {
		t.Fatalf("HTTPReaderErrors=%d want 3 (reader+decode)", in.HTTPReaderErrors)
	}
	if in.UDPTotal != 2 || in.HTTPTotal != 1 {
		t.Fatalf("totals udp=%d http=%d", in.UDPTotal, in.HTTPTotal)
	}
	if in.DroppedCounts["udp_decode"] != 2 || in.DroppedCounts["http_jsonl"] != 1 {
		t.Fatalf("DroppedCounts not propagated: %+v", in.DroppedCounts)
	}
}

func TestRun_BuildsDigestInputWithHealthyHookAndZeroSeq(t *testing.T) {
	stats := newRunStats()
	stats.addUDP(policy.ClassMonitor)
	stats.addHTTP(policy.ClassMonitor)

	in := buildDigestInput(
		stats,
		[]telemetry.BPFStatus{
			{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: true},
		},
		nil, nil, nil, nil, nil,
		"",
		0,
		120,
		networkSectionSnapshot{},
		enforcementSnapshot{},
		nil,
		false,
		forkSectionSnapshot{},
		false,
		false,
		nil,
		fsSectionSnapshot{},
		false,
	)

	if in.UDPDegradedHook || in.HTTPDegradedHook || in.TLSDegradedHook {
		t.Fatal("expected degraded flags false when hook is healthy")
	}
	if in.SeqFirst != 0 || in.SeqLast != 0 {
		t.Fatalf("expected zero seq range when seqLast is zero, got first=%d last=%d", in.SeqFirst, in.SeqLast)
	}
}

func TestRun_BuildsDigestInputMissingHookDefaultsDegraded(t *testing.T) {
	stats := newRunStats()
	in := buildDigestInput(
		stats,
		[]telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		nil, nil, nil, nil, nil,
		"",
		1,
		120,
		networkSectionSnapshot{},
		enforcementSnapshot{},
		nil,
		false,
		forkSectionSnapshot{},
		false,
		false,
		nil,
		fsSectionSnapshot{},
		false,
	)
	if !in.UDPDegradedHook || !in.HTTPDegradedHook || !in.TLSDegradedHook {
		t.Fatal("expected degraded flags true when raw_tp hook status is missing")
	}
}

func TestRun_EnforceAllowlistStartFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, err := compileEnforceAllowlist(ctx, config.Config{
		Mode:           config.ModeEnforce,
		AllowedDomains: nil,
	}, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "requires non-empty allowlist") {
		t.Fatalf("expected non-empty allowlist error, got %v", err)
	}

	_, err = compileEnforceAllowlist(ctx, config.Config{
		Mode:           config.ModeEnforce,
		AllowedDomains: []string{" ", "\t"},
	}, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "requires non-empty allowlist") {
		t.Fatalf("expected effective-empty allowlist error, got %v", err)
	}

	resolver := func(context.Context, string, string) ([]net.IP, error) {
		return nil, nil
	}
	_, err = compileEnforceAllowlist(ctx, config.Config{
		Mode:           config.ModeEnforce,
		AllowedDomains: []string{"example.com"},
	}, resolver, 1)
	if err == nil || !strings.Contains(err.Error(), "effective allowlist is empty") {
		t.Fatalf("expected effective allowlist empty error, got %v", err)
	}

	res, err := compileEnforceAllowlist(ctx, config.Config{
		Mode:           config.ModeEnforce,
		AllowedDomains: []string{"example.com"},
		AllowedIPs:     "1.1.1.1",
	}, resolver, 1)
	if err != nil {
		t.Fatalf("literal allowed-ips should satisfy compile when DNS yields no A records: %v", err)
	}
	if res.AllowedIPv4.Len() != 1 || !res.AllowedIPv4.Contains(net.ParseIP("1.1.1.1")) {
		t.Fatalf("expected single 1.1.1.1 in compiled set, got len=%d", res.AllowedIPv4.Len())
	}
}

// TestRun_EnforceDenyEventEmission checks testAppendDenySample appends JSONL and returns the synthetic
// "enforce deny" error shape used by unit tests. Production readDenyRing drains a short burst of
// denies, cancels the run context, then returns the same error shape (first deny fields).
func TestRun_EnforceDenyEventEmission(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeEnforce,
		EventsLogPath: events,
	}

	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	raw := make([]byte, denyEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 4321)
	binary.LittleEndian.PutUint32(raw[4:8], 5001)
	copy(raw[8:24], []byte("curl"))
	raw[24] = denyProtoTCP
	raw[25] = denyReasonDstNotAllowlisted
	copy(raw[28:32], net.ParseIP("1.2.3.4").To4())
	binary.BigEndian.PutUint16(raw[32:34], 443)

	err := testAppendDenySample(cfg, raw, &seq, &jsonlMu, state)
	if err == nil {
		t.Fatal("expected deny to fail fast with error")
	}
	if !strings.Contains(err.Error(), "enforce deny") {
		t.Fatalf("expected enforce deny error, got %v", err)
	}

	b, readErr := os.ReadFile(events)
	if readErr != nil {
		t.Fatalf("read events log: %v", readErr)
	}
	line := string(b)
	for _, want := range []string{
		`"type":"deny"`,
		`"protocol":"tcp"`,
		`"dst":"1.2.3.4"`,
		`"dport":443`,
		`"reason":"dst_not_allowlisted"`,
		`"mode":"enforce"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("events log missing %q:\n%s", want, line)
		}
	}
	if state.denyCount() != 1 {
		t.Fatalf("denyCount=%d want 1", state.denyCount())
	}
	first := state.firstDeny()
	if first == nil {
		t.Fatal("expected first deny row to be recorded")
	}
	if first.Protocol != "tcp" || first.Dst != "1.2.3.4" || first.Dport != 443 || first.Reason != "dst_not_allowlisted" {
		t.Fatalf("unexpected first deny row: %+v", *first)
	}
}

func TestAppendDenyFromRaw_TwoSamples(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeEnforce,
		EventsLogPath: events,
	}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	rawTCP := make([]byte, denyEventWireSize)
	binary.LittleEndian.PutUint32(rawTCP[0:4], 100)
	binary.LittleEndian.PutUint32(rawTCP[4:8], 200)
	copy(rawTCP[8:24], []byte("curl"))
	rawTCP[24] = denyProtoTCP
	rawTCP[25] = denyReasonDstNotAllowlisted
	copy(rawTCP[28:32], net.ParseIP("10.0.0.1").To4())
	binary.BigEndian.PutUint16(rawTCP[32:34], 443)

	rawUDP := make([]byte, denyEventWireSize)
	binary.LittleEndian.PutUint32(rawUDP[0:4], 101)
	binary.LittleEndian.PutUint32(rawUDP[4:8], 201)
	copy(rawUDP[8:24], []byte("dig"))
	rawUDP[24] = denyProtoUDP
	rawUDP[25] = denyReasonDstNotAllowlisted
	copy(rawUDP[28:32], net.ParseIP("8.8.8.8").To4())
	binary.BigEndian.PutUint16(rawUDP[32:34], 53)

	if _, err := appendDenyFromRaw(cfg, rawTCP, &seq, &jsonlMu, state); err != nil {
		t.Fatalf("append tcp: %v", err)
	}
	if _, err := appendDenyFromRaw(cfg, rawUDP, &seq, &jsonlMu, state); err != nil {
		t.Fatalf("append udp: %v", err)
	}

	if state.denyCount() != 2 {
		t.Fatalf("denyCount=%d want 2", state.denyCount())
	}
	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"protocol":"tcp"`) || !strings.Contains(s, `"protocol":"udp"`) {
		t.Fatalf("expected both protocols in JSONL:\n%s", s)
	}
}

func TestProcessDenyRingSample_InvalidRaw_NoNoteDeny(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeEnforce,
		EventsLogPath: events,
	}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	processDenyRingSample(cfg, []byte{0x01}, &seq, &jsonlMu, state)
	if state.denyCount() != 0 {
		t.Fatalf("decode failure must not noteDeny, got denyCount=%d", state.denyCount())
	}
}

func TestProcessDenyRingSample_JSONLPathIsDir_NoNoteDeny(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	blocked := filepath.Join(dir, "notafile")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Mode:          config.ModeEnforce,
		EventsLogPath: blocked,
	}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	raw := make([]byte, denyEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 100)
	binary.LittleEndian.PutUint32(raw[4:8], 200)
	copy(raw[8:24], []byte("curl"))
	raw[24] = denyProtoTCP
	raw[25] = denyReasonDstNotAllowlisted
	copy(raw[28:32], net.ParseIP("10.0.0.1").To4())
	binary.BigEndian.PutUint16(raw[32:34], 443)

	processDenyRingSample(cfg, raw, &seq, &jsonlMu, state)
	if state.denyCount() != 0 {
		t.Fatalf("JSONL failure must not noteDeny, got denyCount=%d", state.denyCount())
	}
}

func TestBpfDetail_TruncatesUTF8WithoutSplittingRune(t *testing.T) {
	t.Parallel()
	euro := string([]byte{0xe2, 0x82, 0xac})
	long := strings.Repeat("a", 170) + euro + "tail"
	out := bpfDetail(errors.New(long))
	if !utf8.ValidString(out) {
		t.Fatalf("invalid utf-8: %q", out)
	}
	if len(out) > 190 {
		t.Fatalf("detail unexpectedly long: %d", len(out))
	}
}

func TestRun_DetectModeUnchangedForEnforceAllowlistCompile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	res, err := compileEnforceAllowlist(ctx, config.Config{
		Mode:           config.ModeDetect,
		AllowedDomains: nil,
	}, nil, 1)
	if err != nil {
		t.Fatalf("detect mode should not fail enforce preflight: %v", err)
	}
	if res.AllowedIPv4.Len() != 0 || len(res.Domains) != 0 || len(res.UnresolvedDomains) != 0 {
		t.Fatalf("detect mode expected empty compile result, got %#v", res)
	}
}

func TestRun_DenyMappings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		proto    uint8
		reason   uint8
		wantProt string
		wantWhy  string
	}{
		{proto: denyProtoTCP, reason: denyReasonDstNotAllowlisted, wantProt: "tcp", wantWhy: "dst_not_allowlisted"},
		{proto: denyProtoUDP, reason: denyReasonDstNotAllowlisted, wantProt: "udp", wantWhy: "dst_not_allowlisted"},
		{proto: 99, reason: 77, wantProt: "unknown", wantWhy: "unknown"},
	}
	for _, tc := range cases {
		gotProt := denyProtocolLabel(tc.proto)
		gotWhy := denyReasonLabel(tc.reason)
		if gotProt != tc.wantProt || gotWhy != tc.wantWhy {
			t.Fatalf("proto=%d reason=%d got=(%s,%s) want=(%s,%s)", tc.proto, tc.reason, gotProt, gotWhy, tc.wantProt, tc.wantWhy)
		}
	}

	row := denyDigestRowFromEvent(telemetry.DenyEvent{
		TS:       "2026-04-10T00:00:00Z",
		PID:      123,
		Comm:     "curl",
		Protocol: "tcp",
		Dst:      "8.8.8.8",
		Dport:    53,
		Reason:   "dst_not_allowlisted",
	})
	if row != (report.DenyDigestRow{
		TS:       "2026-04-10T00:00:00Z",
		PID:      123,
		Comm:     "curl",
		Protocol: "tcp",
		Dst:      "8.8.8.8",
		Dport:    53,
		Reason:   "dst_not_allowlisted",
	}) {
		t.Fatalf("unexpected deny digest row: %+v", row)
	}
}

func TestPreferRunError_EnforceDenyWinsOverGeneric(t *testing.T) {
	generic := fmt.Errorf("boom")
	deny := newEnforceDenyError(telemetry.DenyEvent{
		Protocol: "tcp",
		Dst:      "1.2.3.4",
		Dport:    443,
		Reason:   "dst_not_allowlisted",
	})
	got := preferRunError(generic, deny)
	if !isEnforceDenyError(got) {
		t.Fatalf("expected enforce deny to win, got %v", got)
	}
}

func TestPreferRunError_IgnoresContextCanceled(t *testing.T) {
	generic := fmt.Errorf("boom")
	got := preferRunError(generic, context.Canceled)
	if got != generic {
		t.Fatalf("expected generic error to remain, got %v", got)
	}
}

func TestLoadIgnoredLPMMap_NilMapIncludesCIDRCount(t *testing.T) {
	_, n, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	err = loadIgnoredLPMMap(nil, []*net.IPNet{n})
	if err == nil {
		t.Fatal("expected nil-map error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ignored_ipv4_lpm map is nil") || !strings.Contains(msg, "1 ignored CIDR") {
		t.Fatalf("expected contextual nil-map error, got: %v", err)
	}
}

func TestLoadIgnoredLPMMap_EmptyNetsNoop(t *testing.T) {
	if err := loadIgnoredLPMMap(nil, nil); err != nil {
		t.Fatalf("expected nil error for empty net list, got %v", err)
	}
}

func TestCapabilityEnabled_RequiresGateAndHealthyHook(t *testing.T) {
	hook := "raw_tp/sys_enter (connect, sendto, http sniff, tls)"
	healthy := []telemetry.BPFStatus{{Name: hook, OK: true}}
	degraded := []telemetry.BPFStatus{{Name: hook, OK: false, Detail: "disabled"}}

	if !capabilityEnabled(true, healthy, hook) {
		t.Fatal("expected capability enabled when gate on and hook healthy")
	}
	if capabilityEnabled(true, degraded, hook) {
		t.Fatal("expected capability disabled when hook degraded")
	}
	if capabilityEnabled(false, healthy, hook) {
		t.Fatal("expected capability disabled when gate off")
	}
}

func TestCapabilityEnabled_MissingHookIsDisabled(t *testing.T) {
	if capabilityEnabled(true, []telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}}, "sched_process_fork") {
		t.Fatal("expected capability disabled when hook status is missing")
	}
}

func TestRun_BuildsDigestInputWithFSSectionState(t *testing.T) {
	stats := newRunStats()
	stats.addFS()
	stats.addFS()

	in := buildDigestInput(
		stats,
		[]telemetry.BPFStatus{
			{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: "disabled"},
		},
		nil, nil, nil, nil, nil,
		"",
		0,
		120,
		networkSectionSnapshot{},
		enforcementSnapshot{},
		nil,
		false,
		forkSectionSnapshot{},
		false,
		false,
		[]report.FSDigestRow{{TS: "t", PID: 1, Comm: "bash", Op: "create", Path: "/tmp/x"}},
		fsSectionSnapshot{readErrors: 1},
		true,
	)

	if !in.FSGate {
		t.Fatal("FSGate should be true")
	}
	if in.FSTotal != 2 {
		t.Fatalf("FSTotal=%d want 2", in.FSTotal)
	}
	if !in.FSDegradedHook {
		t.Fatal("FSDegradedHook should be true when fs hook is degraded")
	}
	if in.FSReaderErrors != 1 {
		t.Fatalf("FSReaderErrors=%d want 1", in.FSReaderErrors)
	}
	if len(in.FSRows) != 1 || in.FSRows[0].Path != "/tmp/x" {
		t.Fatalf("FSRows unexpected: %+v", in.FSRows)
	}
}
