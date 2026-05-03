//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cilium/ebpf"

	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func fillTestDenyRawV4(tgid, tid uint32, comm string, proto, reason uint8, ip net.IP, dport uint16) []byte {
	raw := make([]byte, denyEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], tgid)
	binary.LittleEndian.PutUint32(raw[4:8], tid)
	copy(raw[8:24], comm)
	raw[24] = proto
	raw[25] = reason
	raw[26] = uint8(linuxAFInet)
	raw[27] = 0
	if ip4 := ip.To4(); ip4 != nil {
		copy(raw[28:32], ip4)
	}
	binary.BigEndian.PutUint16(raw[44:46], dport)
	return raw
}

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
		config.Config{Mode: config.ModeDetect},
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
		canarySnapshot{},
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

// stableRingDropKinds lists every stats.addDropped kind used on ring/decode/jsonl paths in agent_linux_*.go (readers + decoders).
func stableRingDropKinds() []string {
	return []string{
		"exec_decode", "exec_jsonl",
		"proc_fork_decode", "proc_fork_jsonl",
		"fs_decode", "fs_jsonl", "fs_cap",
		"tcp_decode", "tcp_jsonl",
		"tls_decode", "tls_jsonl",
		"tls_sni_parse",
		"udp_decode", "udp_jsonl",
		"http_decode", "http_jsonl",
		"http_prefix_parse",
		"dns_decode",
	}
}

func TestRun_DroppedKinds_PropagateToDigestInput(t *testing.T) {
	stats := newRunStats()
	for _, k := range stableRingDropKinds() {
		stats.addDropped(k)
	}

	in := buildDigestInput(
		config.Config{Mode: config.ModeDetect},
		stats,
		[]telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
		nil,
		nil,
		nil,
		nil,
		nil,
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
		canarySnapshot{},
	)

	for _, k := range stableRingDropKinds() {
		if in.DroppedCounts[k] != 1 {
			t.Fatalf("drop kind %s: want count 1, got %+v", k, in.DroppedCounts)
		}
	}
}

func TestRun_BuildsDigestInputWithHealthyHookAndZeroSeq(t *testing.T) {
	stats := newRunStats()
	stats.addUDP(policy.ClassMonitor)
	stats.addHTTP(policy.ClassMonitor)

	in := buildDigestInput(
		config.Config{Mode: config.ModeDetect},
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
		canarySnapshot{},
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
		config.Config{Mode: config.ModeDetect},
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
		canarySnapshot{},
	)
	if !in.UDPDegradedHook || !in.HTTPDegradedHook || !in.TLSDegradedHook {
		t.Fatal("expected degraded flags true when raw_tp hook status is missing")
	}
}

func TestRun_EnforceBackendMetadataReflectsActualBackend(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		cfg          enforceBackendConfig
		lsmAttachErr error
		wantBackend  string
		wantMode     string
	}{
		{
			name: "lsm_backend",
			cfg: enforceBackendConfig{
				modeEnforce: true,
				haveLSM:     true,
			},
			wantBackend: enforceBackendLSM,
			wantMode:    enforceModeLSM,
		},
		{
			name: "cgroup_fallback_after_lsm_attach_error",
			cfg: enforceBackendConfig{
				modeEnforce: true,
				haveLSM:     true,
			},
			lsmAttachErr: errors.New("lsm attach failed"),
			wantBackend:  enforceBackendCgroup,
			wantMode:     enforceModeCgroup,
		},
		{
			name: "cgroup_backend_when_lsm_unavailable",
			cfg: enforceBackendConfig{
				modeEnforce: true,
				haveLSM:     false,
			},
			wantBackend: enforceBackendCgroup,
			wantMode:    enforceModeCgroup,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			outcome := chooseEnforceBackend(tc.cfg, tc.lsmAttachErr)
			if outcome.backend != tc.wantBackend {
				t.Fatalf("backend=%q want %q", outcome.backend, tc.wantBackend)
			}

			stats := newRunStats()
			state := newEnforcementState()
			state.setModeAndAllowlist(enforceModeForBackend(outcome.backend), 1, 0)

			in := buildDigestInput(
				config.Config{Mode: config.ModeEnforce},
				stats,
				[]telemetry.BPFStatus{{Name: "sched_process_exec", OK: true}},
				nil, nil, nil, nil, nil,
				"",
				0,
				120,
				networkSectionSnapshot{},
				state.snapshot(),
				nil,
				false,
				forkSectionSnapshot{},
				false,
				false,
				nil,
				fsSectionSnapshot{},
				false,
				canarySnapshot{},
			)

			if in.EnforcementMode != tc.wantMode {
				t.Fatalf("EnforcementMode=%q want %q", in.EnforcementMode, tc.wantMode)
			}
		})
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

	raw := fillTestDenyRawV4(4321, 5001, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.2.3.4"), 443)

	err := testAppendDenySample(cfg, raw, &seq, &jsonlMu, state, nil)
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
		`"mode":"defend"`,
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

	rawTCP := fillTestDenyRawV4(100, 200, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("10.0.0.1"), 443)

	rawUDP := fillTestDenyRawV4(101, 201, "dig", denyProtoUDP, denyReasonDstNotAllowlisted, net.ParseIP("10.0.0.2"), 53)

	if _, err := appendDenyFromRaw(cfg, rawTCP, &seq, &jsonlMu, state, nil); err != nil {
		t.Fatalf("append tcp: %v", err)
	}
	if _, err := appendDenyFromRaw(cfg, rawUDP, &seq, &jsonlMu, state, nil); err != nil {
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
	if !strings.Contains(s, `"dst":"10.0.0.2"`) {
		t.Fatalf("expected UDP deny IPv4 dst in JSONL:\n%s", s)
	}
}

func TestAppendDenyFromRaw_InvalidPayload(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Mode: config.ModeEnforce}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	_, err := appendDenyFromRaw(cfg, []byte{0x01}, &seq, &jsonlMu, state, nil)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAppendDenyFromRaw_NonIPv4AddressFamilyRejected(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Mode: config.ModeEnforce}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	raw := fillTestDenyRawV4(1, 1, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.1.1.1"), 443)
	raw[26] = 10 // AF_INET6 — Coldstep does not emit or record IPv6 denies

	_, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil)
	if err == nil {
		t.Fatal("expected unsupported address family error")
	}
	if !strings.Contains(err.Error(), "unsupported address family") {
		t.Fatalf("expected AF error, got %v", err)
	}
}

func TestAppendDenyFromRaw_JSONLWriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Mode: config.ModeEnforce, EventsLogPath: blocked}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	raw := fillTestDenyRawV4(1, 1, "", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.1.1.1"), 443)

	_, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil)
	if err == nil {
		t.Fatal("expected append deny jsonl error")
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

	processDenyRingSample(cfg, []byte{0x01}, &seq, &jsonlMu, state, nil)
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

	raw := fillTestDenyRawV4(100, 200, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("10.0.0.1"), 443)

	processDenyRingSample(cfg, raw, &seq, &jsonlMu, state, nil)
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

func TestDigestEnforcementLabel(t *testing.T) {
	t.Parallel()
	enforceCfg := config.Config{Mode: config.ModeEnforce}
	if got := digestEnforcementLabel(enforceCfg, enforcementSnapshot{}); got != "defend" {
		t.Fatalf("empty snap with enforce cfg: got %q want defend", got)
	}
	if got := digestEnforcementLabel(enforceCfg, enforcementSnapshot{mode: enforceModeCgroup}); got != enforceModeCgroup {
		t.Fatalf("non-empty snap: got %q want %s", got, enforceModeCgroup)
	}
	detectCfg := config.Config{Mode: config.ModeDetect}
	if got := digestEnforcementLabel(detectCfg, enforcementSnapshot{mode: "x"}); got != "x" {
		t.Fatalf("detect cfg must pass through snap mode: got %q", got)
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
	_, err = loadIgnoredLPMMap(nil, []*net.IPNet{n})
	if err == nil {
		t.Fatal("expected nil-map error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ignored_ipv4_lpm map is nil") || !strings.Contains(msg, "1 ignored CIDR") {
		t.Fatalf("expected contextual nil-map error, got: %v", err)
	}
}

func TestLoadIgnoredLPMMap_EmptyNetsNoop(t *testing.T) {
	if _, err := loadIgnoredLPMMap(nil, nil); err != nil {
		t.Fatalf("expected nil error for empty net list, got %v", err)
	}
	if _, err := loadIgnoredLPMMap(nil, []*net.IPNet{}); err != nil {
		t.Fatalf("expected nil error for empty net slice, got %v", err)
	}
}

func TestLoadIgnoredLPMMap_NoProgrammableIPv4ReturnsError(t *testing.T) {
	spec := &ebpf.MapSpec{
		Name:       "coldstep_t_ign_lpm_nf",
		Type:       ebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 8,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("ebpf test map unavailable: %v", err)
	}
	defer m.Close()

	_, err = loadIgnoredLPMMap(m, []*net.IPNet{nil})
	if err == nil {
		t.Fatal("expected error when no IPv4 entries could be programmed")
	}
	if !strings.Contains(err.Error(), "no entries programmed") {
		t.Fatalf("expected no entries programmed message, got %v", err)
	}
}

// B-SR-04: Map.Update failures must stay identifiable (prefix + CIDR + %w) for callers like loadEnforceMaps.
func TestLoadIgnoredLPMMap_MapUpdateFailureIsWrapped(t *testing.T) {
	spec := &ebpf.MapSpec{
		Name:       "coldstep_t_ign_lpm",
		Type:       ebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 8,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("ebpf test map unavailable: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close map: %v", err)
	}

	_, n, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadIgnoredLPMMap(m, []*net.IPNet{n})
	if err == nil {
		t.Fatal("expected error programming closed map")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ignored_ipv4_lpm update") {
		t.Fatalf("missing contextual prefix: %v", err)
	}
	if !strings.Contains(msg, "192.0.2.0/24") {
		t.Fatalf("missing CIDR string in message: %v", err)
	}
	if errors.Unwrap(err) == nil {
		t.Fatalf("expected %%w chain from Map.Update: %v", err)
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
		config.Config{Mode: config.ModeDetect},
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
		canarySnapshot{},
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

// Regression: composite action polls .coldstep-ready.json as the runner user while coldstep runs
// under sudo — root-only 0600 caused EACCES; payload is intentionally world-readable.
func TestCheckMapIntegrity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeEnforce,
		EventsLogPath: events,
	}

	// Create mock maps
	enforceSpec := &ebpf.MapSpec{Name: "enforce_cfg", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	enforceCfg, err := ebpf.NewMap(enforceSpec)
	if err != nil {
		t.Skipf("skipping BPF map test: %v (likely missing CAP_BPF/CAP_SYS_ADMIN)", err)
	}
	defer enforceCfg.Close()

	allowedSpec := &ebpf.MapSpec{Name: "allowed_ipv4", Type: ebpf.LPMTrie, KeySize: 8, ValueSize: 1, MaxEntries: 10, Flags: 1}
	allowedIpv4, err := ebpf.NewMap(allowedSpec)
	if err != nil {
		t.Skipf("skipping BPF map test: %v", err)
	}
	defer allowedIpv4.Close()

	ignoredSpec := &ebpf.MapSpec{Name: "ignored_ipv4_lpm", Type: ebpf.LPMTrie, KeySize: 8, ValueSize: 1, MaxEntries: 10, Flags: 1}
	ignoredIpv4, err := ebpf.NewMap(ignoredSpec)
	if err != nil {
		t.Skipf("skipping BPF map test: %v", err)
	}
	defer ignoredIpv4.Close()

	// Initial state
	key0 := uint32(0)
	val1 := uint32(1)
	_ = enforceCfg.Update(&key0, &val1, ebpf.UpdateAny)

	stats := newRunStats()
	state := newEnforcementState()
	state.setModeAndAllowlist("enforce", 2, 1) // Expected: 2 allowed, 1 ignored

	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex

	// Empty snapshot keeps the H-04 re-arm path a no-op for the matched-count
	// phases below; the dedicated TestRearmAllowedFromSnapshot exercises the
	// non-empty re-arm path.
	var snapshot policy.CompileResult
	backoff := newIntegrityBackoff()

	// 1. Initial check (mismatch expected)
	checkMapIntegrity(cfg, enforceCfg, allowedIpv4, ignoredIpv4, snapshot, nil, stats, state, backoff, &seq, &jsonlMu, nil)
	if state.mapIntegrityFailureCount() != 2 {
		t.Fatalf("expected 2 failures (allowed=0, ignored=0), got %d", state.mapIntegrityFailureCount())
	}

	// 2. Fix counts
	kAllowed1 := [8]byte{32, 0, 0, 0, 1, 1, 1, 1}
	kAllowed2 := [8]byte{32, 0, 0, 0, 1, 1, 1, 2}
	v := uint8(1)
	_ = allowedIpv4.Update(&kAllowed1, &v, ebpf.UpdateAny)
	_ = allowedIpv4.Update(&kAllowed2, &v, ebpf.UpdateAny)

	kIgnored := [8]byte{24, 0, 0, 0, 10, 0, 0, 0}
	_ = ignoredIpv4.Update(&kIgnored, &v, ebpf.UpdateAny)

	checkMapIntegrity(cfg, enforceCfg, allowedIpv4, ignoredIpv4, snapshot, nil, stats, state, backoff, &seq, &jsonlMu, nil)
	if state.mapIntegrityFailureCount() != 2 {
		t.Fatalf("expected failures to remain at 2 after clean check, got %d", state.mapIntegrityFailureCount())
	}

	// 3. Tamper with enforce_cfg
	val0 := uint32(0)
	_ = enforceCfg.Update(&key0, &val0, ebpf.UpdateAny)
	checkMapIntegrity(cfg, enforceCfg, allowedIpv4, ignoredIpv4, snapshot, nil, stats, state, backoff, &seq, &jsonlMu, nil)
	if state.mapIntegrityFailureCount() != 3 {
		t.Fatalf("expected 3 failures after enforce_cfg tampering, got %d", state.mapIntegrityFailureCount())
	}

	// Verify revert
	var valCheck uint32
	_ = enforceCfg.Lookup(&key0, &valCheck)
	if valCheck != 1 {
		t.Fatalf("expected enforce_cfg to be reverted to 1, got %d", valCheck)
	}

	// Verify JSONL
	b, _ := os.ReadFile(events)
	s := string(b)
	if !strings.Contains(s, `"type":"bpf_tamper"`) || !strings.Contains(s, `"asset":"map:enforce_cfg"`) {
		t.Fatalf("expected bpf_tamper event in JSONL, got:\n%s", s)
	}
}

// H-04 regression: a count mismatch on allowed_ipv4 must trigger
// rearmAllowedFromSnapshot, deleting tampered keys not in the compiled
// snapshot and re-inserting any missing snapshot keys.
func TestRearmAllowedFromSnapshot_RemovesTamperedAndRestoresMissing(t *testing.T) {
	t.Parallel()
	allowedSpec := &ebpf.MapSpec{Name: "allowed_ipv4", Type: ebpf.LPMTrie, KeySize: 8, ValueSize: 1, MaxEntries: 16, Flags: 1}
	allowedIpv4, err := ebpf.NewMap(allowedSpec)
	if err != nil {
		t.Skipf("skipping BPF map test: %v (likely missing CAP_BPF/CAP_SYS_ADMIN)", err)
	}
	defer allowedIpv4.Close()

	// Snapshot says 1.1.1.1 and 1.1.1.2 are the only allowed IPv4 entries.
	var snapshot policy.CompileResult
	snapshot.AllowedIPv4.Add(net.IPv4(1, 1, 1, 1))
	snapshot.AllowedIPv4.Add(net.IPv4(1, 1, 1, 2))

	// Pre-load the map with the legitimate entry 1.1.1.1, a tampered extra
	// entry 9.9.9.9, and intentionally omit 1.1.1.2 to force the re-arm to
	// also restore it.
	v := uint8(1)
	tamper := [8]byte{32, 0, 0, 0, 9, 9, 9, 9}
	keep := [8]byte{32, 0, 0, 0, 1, 1, 1, 1}
	if err := allowedIpv4.Update(&keep, &v, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed legit key: %v", err)
	}
	if err := allowedIpv4.Update(&tamper, &v, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed tampered key: %v", err)
	}

	added, removed, err := rearmAllowedFromSnapshot(allowedIpv4, snapshot, nil)
	if err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 stale key removed (9.9.9.9), got removed=%d", removed)
	}
	// reconcileLPMMap counts only keys that were absent before upsert (not every UpdateAny).
	if added != 1 {
		t.Fatalf("expected 1 new key inserted (1.1.1.2); 1.1.1.1 was already present, got added=%d", added)
	}

	// Walk the map post-rearm and confirm only the snapshot keys remain.
	want := map[[8]byte]bool{
		{32, 0, 0, 0, 1, 1, 1, 1}: true,
		{32, 0, 0, 0, 1, 1, 1, 2}: true,
	}
	got := map[[8]byte]bool{}
	iter := allowedIpv4.Iterate()
	var k [8]byte
	var val uint8
	for iter.Next(&k, &val) {
		got[k] = true
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("post-rearm iterate: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("post-rearm key count = %d; want %d (got=%v)", len(got), len(want), got)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing expected snapshot key in map: %v", k)
		}
	}
	if got[tamper] {
		t.Errorf("tampered key 9.9.9.9 still present after re-arm: %v", got)
	}
}

// M-13 regression: integrityBackoff must escalate the first failure for an
// asset (return true) and dedupe subsequent failures inside the backoff
// window (return false), and a clear() call must re-escalate the next
// failure.
func TestIntegrityBackoff_DeduplicatesAndClears(t *testing.T) {
	t.Parallel()
	b := newIntegrityBackoff()
	if !b.noteFailure("map:enforce_cfg") {
		t.Fatal("first failure should escalate (true)")
	}
	if b.noteFailure("map:enforce_cfg") {
		t.Fatal("immediate repeat should dedupe (false)")
	}
	if !b.noteFailure("map:allowed_ipv4") {
		t.Fatal("first failure for a different asset should escalate independently")
	}

	// clear() simulates a successful re-arm; the next failure escalates again.
	b.clear("map:enforce_cfg")
	if !b.noteFailure("map:enforce_cfg") {
		t.Fatal("post-clear failure should re-escalate (true)")
	}

	// Fast-forward the per-asset timestamp past the backoff window and confirm
	// re-escalation without going through clear().
	b.mu.Lock()
	b.lastFail["map:allowed_ipv4"] = time.Now().Add(-2 * integrityBackoffWindow)
	b.mu.Unlock()
	if !b.noteFailure("map:allowed_ipv4") {
		t.Fatal("failure outside backoff window should re-escalate (true)")
	}
}

// Regression: composite action polls .coldstep-ready.json as the runner user while coldstep runs
// under sudo — root-only 0600 caused EACCES; payload is intentionally world-readable.
func TestWriteAgentStatus_WorldReadableAndJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".coldstep-ready.json")
	if err := writeAgentStatus(p, true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	perm := fi.Mode().Perm()
	if perm&0o004 == 0 {
		t.Fatalf("status file must be readable by other (GitHub Actions runner); mode=%#o", perm)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		OK      bool `json:"ok"`
		Version int  `json:"version"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json: %v body=%q", err, string(raw))
	}
	if !m.OK || m.Version != 1 {
		t.Fatalf("unexpected payload: %+v", m)
	}
	if err := writeAgentStatus(p, false); err != nil {
		t.Fatal(err)
	}
	raw2, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw2, &m); err != nil {
		t.Fatal(err)
	}
	if m.OK {
		t.Fatal("expected ok false")
	}
}

// TestAppendDenyFromRaw_ConcurrentSeqMatchesFileOrder is the M-05 regression: every JSONL deny
// line must carry a strictly increasing seq, matching the order it was appended to the file. With
// the buggy code (seq.Next() outside jsonlMu) two goroutines could pick (1, 2) but write in the
// (2, 1) order. Post-fix, seq.Next() is inside jsonlMu so file order is monotonic with seq.
func TestAppendDenyFromRaw_ConcurrentSeqMatchesFileOrder(t *testing.T) {
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

	const writers = 32
	const perWriter = 8
	var wg sync.WaitGroup
	wg.Add(writers)
	errCh := make(chan error, writers*perWriter)
	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				raw := fillTestDenyRawV4(uint32(w), uint32(i), "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.2.3.4"), 443)
				if _, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil); err != nil {
					errCh <- fmt.Errorf("worker %d iter %d: %w", w, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("append failure: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if got, want := len(lines), writers*perWriter; got != want {
		t.Fatalf("line count=%d want %d", got, want)
	}
	var prevSeq uint64
	for i, line := range lines {
		var ev struct {
			Seq uint64 `json:"seq"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d unmarshal: %v\nline=%q", i, err, line)
		}
		if ev.Seq == 0 {
			t.Fatalf("line %d: seq=0 (must be assigned under jsonlMu)", i)
		}
		if i > 0 && ev.Seq <= prevSeq {
			t.Fatalf("line %d: seq=%d not strictly greater than prev=%d (M-05 ordering violated)", i, ev.Seq, prevSeq)
		}
		prevSeq = ev.Seq
	}
	if prevSeq != uint64(writers*perWriter) {
		t.Fatalf("last seq=%d want %d", prevSeq, writers*perWriter)
	}
}

// TestAppendDenyFromRaw_NoEventsLogDoesNotConsumeSeq is the M-06 regression: when EventsLogPath
// is empty, decoded denies must NOT advance the shared SeqGen, so digest SeqLast cannot overstate
// the number of JSONL lines actually written. State.noteDeny still fires regardless.
func TestAppendDenyFromRaw_NoEventsLogDoesNotConsumeSeq(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Mode: config.ModeEnforce}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	raw := fillTestDenyRawV4(1, 1, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.2.3.4"), 443)
	for i := 0; i < 5; i++ {
		ev, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if ev.Seq != 0 {
			t.Fatalf("iter %d: deny.Seq=%d, want 0 when EventsLogPath empty (M-06)", i, ev.Seq)
		}
	}
	if got := seq.Last(); got != 0 {
		t.Fatalf("seq.Last()=%d, want 0 — seq must not advance when EventsLogPath is empty (M-06)", got)
	}
	if state.denyCount() != 5 {
		t.Fatalf("denyCount=%d want 5 (state must still note denies regardless of JSONL path)", state.denyCount())
	}
}

// TestReadUint32CounterMap_KeyNotExistReturnsZeroSilently is the M-07 regression for the legitimate
// "key not yet written" path: BPF programs use BPF_NOEXIST + ATOMIC update before incrementing, so
// a never-touched counter map has no key 0 entry. Lookup must return ErrKeyNotExist, the helper
// must surface 0, and it must NOT log (that case is normal at agent startup).
func TestReadUint32CounterMap_KeyNotExistReturnsZeroSilently(t *testing.T) {
	spec := &ebpf.MapSpec{
		Name:       "coldstep_t_counter_nf",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("ebpf test map unavailable: %v (likely missing CAP_BPF/CAP_SYS_ADMIN)", err)
	}
	defer m.Close()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if got := readUint32CounterMap(m, "tester"); got != 0 {
		t.Fatalf("expected 0 on ErrKeyNotExist, got %d", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no log output on ErrKeyNotExist, got: %q", buf.String())
	}

	var probeKey uint32
	var probeVal uint32
	if err := m.Lookup(&probeKey, &probeVal); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("test setup invariant: empty Hash map Lookup must return ErrKeyNotExist, got %v", err)
	}
}

// TestReadUint32CounterMap_OtherErrorReturnsZeroAndLogs is the M-07 regression for the real-error
// path: a closed (or otherwise unreadable) map yields a non-ErrKeyNotExist error. The helper must
// log a WARN with helper + err so operators can distinguish "counter is genuinely zero" from "map
// is broken", and still return 0 so downstream digest paths keep working.
func TestReadUint32CounterMap_OtherErrorReturnsZeroAndLogs(t *testing.T) {
	spec := &ebpf.MapSpec{
		Name:       "coldstep_t_counter_closed",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("ebpf test map unavailable: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close map: %v", err)
	}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if got := readUint32CounterMap(m, "tester"); got != 0 {
		t.Fatalf("expected 0 on closed-map error, got %d", got)
	}
	out := buf.String()
	if !strings.Contains(out, "uint32 counter map lookup failed") {
		t.Fatalf("expected warn log, got: %q", out)
	}
	if !strings.Contains(out, "helper=tester") {
		t.Fatalf("expected helper=tester attribute in log, got: %q", out)
	}
	if !strings.Contains(out, "err=") {
		t.Fatalf("expected err attribute in log, got: %q", out)
	}
}

// TestReadUint32PerCPUArraySum_OtherErrorReturnsZeroAndLogs mirrors M-07 for PERCPU_ARRAY counters
// (reserve-failure telemetry maps): unreadable map → WARN + 0, digest paths keep progressing.
func TestReadUint32PerCPUArraySum_OtherErrorReturnsZeroAndLogs(t *testing.T) {
	spec := &ebpf.MapSpec{
		Name:       "coldstep_t_percpu_closed",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("ebpf test map unavailable: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close map: %v", err)
	}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if got := readUint32PerCPUArraySum(m, "tester"); got != 0 {
		t.Fatalf("expected 0 on closed-map error, got %d", got)
	}
	out := buf.String()
	if !strings.Contains(out, "percpu uint32 map lookup failed") {
		t.Fatalf("expected warn log, got: %q", out)
	}
	if !strings.Contains(out, "helper=tester") {
		t.Fatalf("expected helper=tester attribute in log, got: %q", out)
	}
	if !strings.Contains(out, "err=") {
		t.Fatalf("expected err attribute in log, got: %q", out)
	}
}

// TestReadUint32CounterMap_NilMapReturnsZero guards against a nil *ebpf.Map (e.g. a never-loaded
// optional collection) panicking inside Lookup. Helper must early-return 0 silently.
func TestReadUint32CounterMap_NilMapReturnsZero(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if got := readUint32CounterMap(nil, "tester"); got != 0 {
		t.Fatalf("expected 0 on nil map, got %d", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no log output on nil map, got: %q", buf.String())
	}
}
