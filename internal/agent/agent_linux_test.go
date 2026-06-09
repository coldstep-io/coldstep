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

func TestRun_DefendAllowlistStartFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, err := compileDefendAllowlist(ctx, config.Config{
		Mode:           config.ModeDefend,
		AllowedDomains: nil,
	}, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "requires non-empty allowlist") {
		t.Fatalf("expected non-empty allowlist error, got %v", err)
	}

	_, err = compileDefendAllowlist(ctx, config.Config{
		Mode:           config.ModeDefend,
		AllowedDomains: []string{" ", "\t"},
	}, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "requires non-empty allowlist") {
		t.Fatalf("expected effective-empty allowlist error, got %v", err)
	}

	resolver := func(context.Context, string, string) ([]net.IP, error) {
		return nil, nil
	}
	_, err = compileDefendAllowlist(ctx, config.Config{
		Mode:           config.ModeDefend,
		AllowedDomains: []string{"example.com"},
	}, resolver, 1)
	if err == nil || !strings.Contains(err.Error(), "effective allowlist is empty") {
		t.Fatalf("expected effective allowlist empty error, got %v", err)
	}

	res, err := compileDefendAllowlist(ctx, config.Config{
		Mode:           config.ModeDefend,
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

// TestRun_DefendDenyEventEmission checks testAppendDenySample appends JSONL and returns the synthetic
// "defend deny" error shape used by unit tests. Production readDenyRing drains a short burst of
// denies, cancels the run context, then returns the same error shape (first deny fields).
func TestRun_DefendDenyEventEmission(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeDefend,
		EventsLogPath: events,
	}

	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := fillTestDenyRawV4(4321, 5001, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.2.3.4"), 443)

	err := testAppendDenySample(cfg, raw, &seq, &jsonlMu, state, nil, "cgroup", nil)
	if err == nil {
		t.Fatal("expected deny to fail fast with error")
	}
	if !strings.Contains(err.Error(), "defend deny") {
		t.Fatalf("expected defend deny error, got %v", err)
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
		`"hook_family":"cgroup"`,
		`"match_kind":"unknown"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("events log missing %q:\n%s", want, line)
		}
	}
	if state.denyCount() != 1 {
		t.Fatalf("denyCount=%d want 1", state.denyCount())
	}
}

func TestAppendDenyFromRaw_MatchKindDNSCache(t *testing.T) {
	t.Parallel()
	orig := dnsNow
	defer func() { dnsNow = orig }()
	dnsNow = func() time.Time { return time.Unix(50_000, 0).UTC() }

	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeDefend,
		EventsLogPath: events,
	}
	dc := NewDNSCache()
	dc.AddFromPacket(dnsReplySingleA([4]byte{9, 9, 9, 9}, 'x', 600))

	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()
	raw := fillTestDenyRawV4(1, 2, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("9.9.9.9"), 443)
	if _, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "lsm", dc); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"hook_family":"lsm"`) || !strings.Contains(s, `"match_kind":"dns_cache"`) {
		t.Fatalf("expected hook_family lsm and match_kind dns_cache:\n%s", s)
	}
}

func TestAppendDenyFromRaw_TwoSamples(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeDefend,
		EventsLogPath: events,
	}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	rawTCP := fillTestDenyRawV4(100, 200, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("10.0.0.1"), 443)

	rawUDP := fillTestDenyRawV4(101, 201, "dig", denyProtoUDP, denyReasonDstNotAllowlisted, net.ParseIP("10.0.0.2"), 53)

	if _, err := appendDenyFromRaw(cfg, rawTCP, &seq, &jsonlMu, state, nil, "", nil); err != nil {
		t.Fatalf("append tcp: %v", err)
	}
	if _, err := appendDenyFromRaw(cfg, rawUDP, &seq, &jsonlMu, state, nil, "", nil); err != nil {
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

// TestAppendDenyFromRaw_CrossLayerDedup verifies the cgroup+LSM dedup: one
// blocked syscall reported by both hook families within the window emits a
// single JSONL line and counts once, with the twin tallied as corroborated.
func TestAppendDenyFromRaw_CrossLayerDedup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{Mode: config.ModeDefend, EventsLogPath: events}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := fillTestDenyRawV4(4321, 5001, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.2.3.4"), 443)

	// Same logical deny, both hook families.
	if _, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "cgroup", nil); err != nil {
		t.Fatalf("cgroup deny: %v", err)
	}
	if _, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "lsm", nil); err != nil {
		t.Fatalf("lsm deny: %v", err)
	}

	if got := state.denyCount(); got != 1 {
		t.Fatalf("denyCount=%d want 1 (cross-layer twin must not double-count)", got)
	}
	if got := state.denyCorroborated(); got != 1 {
		t.Fatalf("denyCorroborated=%d want 1", got)
	}
	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if n := strings.Count(string(b), `"type":"deny"`); n != 1 {
		t.Fatalf("expected exactly 1 deny JSONL line, got %d:\n%s", n, string(b))
	}
}

// TestAppendDenyFromRaw_SameFamilyNotDeduped verifies genuine repeats on the
// same hook family (e.g. a retry loop) are never collapsed — only cross-family
// twins are.
func TestAppendDenyFromRaw_SameFamilyNotDeduped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{Mode: config.ModeDefend, EventsLogPath: events}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := fillTestDenyRawV4(7, 8, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("5.6.7.8"), 443)

	for i := 0; i < 3; i++ {
		if _, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "cgroup", nil); err != nil {
			t.Fatalf("cgroup deny %d: %v", i, err)
		}
	}
	if got := state.denyCount(); got != 3 {
		t.Fatalf("denyCount=%d want 3 (same-family repeats must all emit)", got)
	}
	if got := state.denyCorroborated(); got != 0 {
		t.Fatalf("denyCorroborated=%d want 0", got)
	}
}

// TestAppendDenyFromRaw_DistinctDstCrossFamily verifies cross-family denies to
// DIFFERENT destinations are both real and both emit.
func TestAppendDenyFromRaw_DistinctDstCrossFamily(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{Mode: config.ModeDefend, EventsLogPath: events}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	rawA := fillTestDenyRawV4(1, 1, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.1.1.1"), 443)
	rawB := fillTestDenyRawV4(1, 1, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("2.2.2.2"), 443)

	if _, err := appendDenyFromRaw(cfg, rawA, &seq, &jsonlMu, state, nil, "cgroup", nil); err != nil {
		t.Fatalf("deny A: %v", err)
	}
	if _, err := appendDenyFromRaw(cfg, rawB, &seq, &jsonlMu, state, nil, "lsm", nil); err != nil {
		t.Fatalf("deny B: %v", err)
	}
	if got := state.denyCount(); got != 2 {
		t.Fatalf("denyCount=%d want 2 (distinct dst must not dedup)", got)
	}
	if got := state.denyCorroborated(); got != 0 {
		t.Fatalf("denyCorroborated=%d want 0", got)
	}
}

// TestShouldEmitDeny_BackwardClockNotFresh verifies a wall-clock step backward
// (NTP/VM adjust between two denies) does not satisfy the dedup window: the
// cross-family second deny must emit rather than be suppressed as a twin.
func TestShouldEmitDeny_BackwardClockNotFresh(t *testing.T) {
	t.Parallel()
	state := newDefendState()
	key := denyDedupKey{tgid: 1, tid: 2, dst: "1.2.3.4", dport: 443, protocol: "tcp"}

	if !state.shouldEmitDeny(key, "cgroup", 5_000_000_000) {
		t.Fatalf("first deny must emit")
	}
	// Clock steps backward 400ms: delta is negative, so the prior entry must
	// not count as fresh and the deny must emit.
	if !state.shouldEmitDeny(key, "lsm", 4_600_000_000) {
		t.Fatalf("deny after backward clock step must emit, not corroborate")
	}
	if got := state.denyCorroborated(); got != 0 {
		t.Fatalf("denyCorroborated=%d want 0", got)
	}
}

func TestAppendDenyFromRaw_InvalidPayload(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Mode: config.ModeDefend}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	_, err := appendDenyFromRaw(cfg, []byte{0x01}, &seq, &jsonlMu, state, nil, "", nil)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAppendDenyFromRaw_UnknownAddressFamilyRejected(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Mode: config.ModeDefend}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := fillTestDenyRawV4(1, 1, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.1.1.1"), 443)
	raw[26] = 17 // AF_PACKET — only AF_INET / AF_INET6 are emitted by defend.

	_, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "", nil)
	if err == nil {
		t.Fatal("expected unsupported address family error")
	}
	if !strings.Contains(err.Error(), "unsupported address family") {
		t.Fatalf("expected AF error, got %v", err)
	}
}

func TestAppendDenyFromRaw_IPv6DenyDecoded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{Mode: config.ModeDefend, EventsLogPath: logPath}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := make([]byte, denyEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 7)
	binary.LittleEndian.PutUint32(raw[4:8], 7)
	copy(raw[8:24], "curl")
	raw[24] = denyProtoTCP
	raw[25] = denyReasonDstNotAllowlisted
	raw[26] = linuxAFInet6
	ip6 := net.ParseIP("2001:db8::1").To16()
	copy(raw[28:44], ip6)
	binary.BigEndian.PutUint16(raw[44:46], 443)

	deny, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "cgroup", nil)
	if err != nil {
		t.Fatalf("appendDenyFromRaw: %v", err)
	}
	if deny.Dst != "2001:db8::1" {
		t.Fatalf("Dst=%q want 2001:db8::1", deny.Dst)
	}
	if deny.Dport != 443 || deny.Protocol != "tcp" {
		t.Fatalf("Dport=%d Protocol=%q", deny.Dport, deny.Protocol)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read events.jsonl: %v", err)
	}
	if !bytes.Contains(data, []byte(`"dst":"2001:db8::1"`)) {
		t.Fatalf("expected IPv6 dst in JSONL, got %s", string(data))
	}
}

func TestAppendDenyFromRaw_JSONLWriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Mode: config.ModeDefend, EventsLogPath: blocked}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := fillTestDenyRawV4(1, 1, "", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.1.1.1"), 443)

	_, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "", nil)
	if err == nil {
		t.Fatal("expected append deny jsonl error")
	}
}

func TestProcessDenyRingSample_InvalidRaw_NoNoteDeny(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeDefend,
		EventsLogPath: events,
	}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	processDenyRingSample(cfg, []byte{0x01}, &seq, &jsonlMu, state, nil, "", nil)
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
		Mode:          config.ModeDefend,
		EventsLogPath: blocked,
	}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := fillTestDenyRawV4(100, 200, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("10.0.0.1"), 443)

	processDenyRingSample(cfg, raw, &seq, &jsonlMu, state, nil, "", nil)
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

func TestDigestDefendLabel(t *testing.T) {
	t.Parallel()
	defendCfg := config.Config{Mode: config.ModeDefend}
	if got := digestDefendLabel(defendCfg, defendSnapshot{}); got != "defend" {
		t.Fatalf("empty snap with defend cfg: got %q want defend", got)
	}
	if got := digestDefendLabel(defendCfg, defendSnapshot{mode: defendModeCgroup}); got != defendModeCgroup {
		t.Fatalf("non-empty snap: got %q want %s", got, defendModeCgroup)
	}
	detectCfg := config.Config{Mode: config.ModeDetect}
	if got := digestDefendLabel(detectCfg, defendSnapshot{mode: "x"}); got != "x" {
		t.Fatalf("detect cfg must pass through snap mode: got %q", got)
	}
}

func TestRun_DetectModeUnchangedForDefendAllowlistCompile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	res, err := compileDefendAllowlist(ctx, config.Config{
		Mode:           config.ModeDetect,
		AllowedDomains: nil,
	}, nil, 1)
	if err != nil {
		t.Fatalf("detect mode should not fail defend preflight: %v", err)
	}
	if res.AllowedIPv4.Len() != 0 || len(res.Domains) != 0 || len(res.UnresolvedDomains) != 0 {
		t.Fatalf("detect mode expected empty compile result, got %#v", res)
	}
}

func TestPreferRunError_DefendDenyWinsOverGeneric(t *testing.T) {
	generic := fmt.Errorf("boom")
	deny := newDefendDenyError(telemetry.DenyEvent{
		Protocol: "tcp",
		Dst:      "1.2.3.4",
		Dport:    443,
		Reason:   "dst_not_allowlisted",
	})
	got := preferRunError(generic, deny)
	if !isDefendDenyError(got) {
		t.Fatalf("expected defend deny to win, got %v", got)
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

func TestBuildAllowedLPMPlan_DeduplicatesAcrossIPAndCIDR(t *testing.T) {
	ipKeys := map[[4]byte]struct{}{
		{1, 1, 1, 1}: {},
		{1, 1, 1, 2}: {},
	}
	_, cidr32a, err := net.ParseCIDR("1.1.1.1/32")
	if err != nil {
		t.Fatal(err)
	}
	_, cidr24, err := net.ParseCIDR("1.1.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	plan, err := buildAllowedLPMPlan("allowed_ipv4", ipKeys, []*net.IPNet{cidr32a, cidr24})
	if err != nil {
		t.Fatalf("buildAllowedLPMPlan: %v", err)
	}
	// 1.1.1.1/32 exists in both ipKeys and literal nets; should be counted once.
	if plan.totalEntries != 3 {
		t.Fatalf("totalEntries=%d want 3", plan.totalEntries)
	}
}

func TestBuildAllowedLPMPlan_RejectsMalformedCIDRInput(t *testing.T) {
	ipKeys := map[[4]byte]struct{}{
		{1, 1, 1, 1}: {},
	}
	invalid := &net.IPNet{
		IP:   net.ParseIP("2001:db8::"),
		Mask: net.CIDRMask(64, 128),
	}
	_, err := buildAllowedLPMPlan("allowed_ipv4", ipKeys, []*net.IPNet{invalid})
	if err == nil {
		t.Fatal("expected malformed CIDR error")
	}
	if !strings.Contains(err.Error(), "non-IPv4 CIDR") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// B-SR-04: Map.Update failures must stay identifiable (prefix + CIDR + %w) for callers like loadDefendMaps.
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

// Regression: composite action polls .coldstep-ready.json as the runner user while coldstep runs
// under sudo — root-only 0600 caused EACCES; payload is intentionally world-readable.
func TestCheckMapIntegrity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	cfg := config.Config{
		Mode:          config.ModeDefend,
		EventsLogPath: events,
	}

	// Create mock maps
	defendSpec := &ebpf.MapSpec{Name: "defend_cfg", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	defendCfg, err := ebpf.NewMap(defendSpec)
	if err != nil {
		t.Skipf("skipping BPF map test: %v (likely missing CAP_BPF/CAP_SYS_ADMIN)", err)
	}
	defer defendCfg.Close()

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
	_ = defendCfg.Update(&key0, &val1, ebpf.UpdateAny)

	stats := newRunStats()
	state := newDefendState()
	state.setModeAndAllowlist("defend", 2, 1) // Expected: 2 allowed, 1 ignored

	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex

	// Empty snapshot keeps the H-04 re-arm path a no-op for the matched-count
	// phases below; the dedicated TestRearmAllowedFromSnapshot exercises the
	// non-empty re-arm path.
	var snapshot policy.CompileResult
	backoff := newIntegrityBackoff()

	// 1. Initial check (mismatch expected)
	checkMapIntegrity(cfg, defendCfg, allowedIpv4, ignoredIpv4, snapshot, nil, stats, state, backoff, &seq, &jsonlMu, nil)
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

	checkMapIntegrity(cfg, defendCfg, allowedIpv4, ignoredIpv4, snapshot, nil, stats, state, backoff, &seq, &jsonlMu, nil)
	if state.mapIntegrityFailureCount() != 2 {
		t.Fatalf("expected failures to remain at 2 after clean check, got %d", state.mapIntegrityFailureCount())
	}

	// 3. Tamper with defend_cfg
	val0 := uint32(0)
	_ = defendCfg.Update(&key0, &val0, ebpf.UpdateAny)
	checkMapIntegrity(cfg, defendCfg, allowedIpv4, ignoredIpv4, snapshot, nil, stats, state, backoff, &seq, &jsonlMu, nil)
	if state.mapIntegrityFailureCount() != 3 {
		t.Fatalf("expected 3 failures after defend_cfg tampering, got %d", state.mapIntegrityFailureCount())
	}

	// Verify revert
	var valCheck uint32
	_ = defendCfg.Lookup(&key0, &valCheck)
	if valCheck != 1 {
		t.Fatalf("expected defend_cfg to be reverted to 1, got %d", valCheck)
	}

	// Verify JSONL
	b, _ := os.ReadFile(events)
	s := string(b)
	if !strings.Contains(s, `"type":"bpf_tamper"`) || !strings.Contains(s, `"asset":"map:defend_cfg"`) {
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
	if !b.noteFailure("map:defend_cfg") {
		t.Fatal("first failure should escalate (true)")
	}
	if b.noteFailure("map:defend_cfg") {
		t.Fatal("immediate repeat should dedupe (false)")
	}
	if !b.noteFailure("map:allowed_ipv4") {
		t.Fatal("first failure for a different asset should escalate independently")
	}

	// clear() simulates a successful re-arm; the next failure escalates again.
	b.clear("map:defend_cfg")
	if !b.noteFailure("map:defend_cfg") {
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
		Mode:          config.ModeDefend,
		EventsLogPath: events,
	}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

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
				if _, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "", nil); err != nil {
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
	cfg := config.Config{Mode: config.ModeDefend}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newDefendState()

	raw := fillTestDenyRawV4(1, 1, "curl", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.2.3.4"), 443)
	for i := 0; i < 5; i++ {
		ev, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state, nil, "", nil)
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

// TestReadUint32PerCPUArraySum_NilMapReturnsZero guards against a nil *ebpf.Map (e.g. a never-loaded
// optional collection) panicking inside Lookup. Helper must early-return 0 silently.
func TestReadUint32PerCPUArraySum_NilMapReturnsZero(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if got := readUint32PerCPUArraySum(nil, "tester"); got != 0 {
		t.Fatalf("expected 0 on nil map, got %d", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no log output on nil map, got: %q", buf.String())
	}
}

// TestBuildDroppedEventsMap_OmitsZerosAndNilWhenClean asserts the H2 shutdown
// meta surface: when no ringbuf reserve failed, the map is nil so MetaEvent's
// omitempty hides the field. When some channels failed, the map contains only
// the non-zero entries keyed by BPF-counter-name-minus-suffix.
func TestBuildDroppedEventsMap_OmitsZerosAndNilWhenClean(t *testing.T) {
	stats := newRunStats()
	defst := newDefendState()
	if got := buildDroppedEventsMap(stats, defst); got != nil {
		t.Fatalf("expected nil map when all counters zero, got %#v", got)
	}

	stats.setConnectRingbufReserveFailures(3)
	stats.setUDPRingbufReserveFailures(0)
	stats.setHTTPRingbufReserveFailures(1)
	stats.setTLSRingbufReserveFailures(0)
	stats.setIoUringRingbufReserveFailures(2)
	defst.setDenyReserveFailures(5)

	got := buildDroppedEventsMap(stats, defst)
	want := map[string]uint64{
		"connect":  3,
		"http":     1,
		"io_uring": 2,
		"deny":     5,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("key %q: got %d, want %d (full map: %v)", k, got[k], v, got)
		}
	}
	if _, ok := got["udp"]; ok {
		t.Fatalf("zero-valued udp key should be omitted, got %v", got)
	}
	if _, ok := got["tls"]; ok {
		t.Fatalf("zero-valued tls key should be omitted, got %v", got)
	}
}

// TestBuildDroppedEventsMap_NilDefendState guards the defend-disabled path
// (detect-only runs construct no defendState — historically a nil pointer).
func TestBuildDroppedEventsMap_NilDefendState(t *testing.T) {
	stats := newRunStats()
	stats.setUDPRingbufReserveFailures(7)
	got := buildDroppedEventsMap(stats, nil)
	if got["udp"] != 7 {
		t.Fatalf("expected udp=7, got %v", got)
	}
	if _, ok := got["deny"]; ok {
		t.Fatalf("deny key should be absent when defendState is nil, got %v", got)
	}
}

// TestRunStats_AddQUICObserved exercises the H19 PossibleQUIC per-run
// counter. The agent's UDP ring reader calls addQUICObserved exactly once
// per UDPEvent whose dport == 443; quicObservedTotal is read at shutdown
// and surfaced on CoverageReport.QuicObserved.
func TestRunStats_AddQUICObserved(t *testing.T) {
	stats := newRunStats()
	if got := stats.quicObservedTotal(); got != 0 {
		t.Fatalf("fresh runStats quicObservedTotal = %d, want 0", got)
	}
	stats.addQUICObserved()
	stats.addQUICObserved()
	stats.addQUICObserved()
	if got := stats.quicObservedTotal(); got != 3 {
		t.Fatalf("after 3 increments quicObservedTotal = %d, want 3", got)
	}
}

// TestUDPEvent_PossibleQUIC_PortPredicate locks the H19 H19 rule: the
// per-event flag is true exactly when DstPort == 443, mirroring the agent's
// `possibleQUIC := port == 443` decision in readUDPRing. Non-443 ports
// (including the common cleartext-HTTP and DNS-over-UDP ports) must leave
// the flag false so the field stays omitempty in the JSONL.
func TestUDPEvent_PossibleQUIC_PortPredicate(t *testing.T) {
	cases := []struct {
		port uint16
		want bool
	}{
		{443, true},
		{80, false},
		{53, false},
		{0, false},
		{4433, false},
		{8443, false},
	}
	for _, tc := range cases {
		got := tc.port == 443
		if got != tc.want {
			t.Fatalf("PossibleQUIC predicate for dport=%d: got %v, want %v", tc.port, got, tc.want)
		}
		ev := telemetry.UDPEvent{Type: "udp", Dport: tc.port, PossibleQUIC: got}
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if tc.want {
			if !strings.Contains(string(b), `"possible_quic":true`) {
				t.Fatalf("dport=%d expected possible_quic:true in JSON, got %s", tc.port, b)
			}
		} else if strings.Contains(string(b), `possible_quic`) {
			t.Fatalf("dport=%d should omit possible_quic, got %s", tc.port, b)
		}
	}
}

func TestRunStats_EgressBackstop(t *testing.T) {
	s := newRunStats()
	s.addEgressBackstop("203.0.113.7")
	s.addEgressBackstop("203.0.113.7") // dup dst
	s.addEgressBackstop("198.51.100.9")
	s.setEgressBackstopReserveFailures(2)
	if got := s.egressBackstopCount(); got != 3 {
		t.Fatalf("count=%d want 3", got)
	}
	dsts := s.egressBackstopDstList()
	if len(dsts) != 2 || dsts[0] != "198.51.100.9" || dsts[1] != "203.0.113.7" {
		t.Fatalf("dsts=%v want sorted distinct", dsts)
	}
	if got := s.egressBackstopReserveFailures(); got != 2 {
		t.Fatalf("reserveFailures=%d want 2", got)
	}
}

func TestRunStats_BpfSelfDefense(t *testing.T) {
	s := newRunStats()
	s.addBpfSelfDefense()
	s.addBpfSelfDefense()
	s.setBpfSelfDefenseReserveFailures(5)
	if got := s.bpfSelfDefenseCount(); got != 2 {
		t.Fatalf("count=%d want 2", got)
	}
	if got := s.bpfSelfDefenseReserveFailures(); got != 5 {
		t.Fatalf("reserveFailures=%d want 5", got)
	}
}
