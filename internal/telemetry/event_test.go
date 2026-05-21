package telemetry

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEventType(t *testing.T) {
	if got := EventType([]byte(`{"type":"tcp","seq":1}`)); got != "tcp" {
		t.Fatalf("got %q", got)
	}
	if got := EventType([]byte(`not json`)); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactPathForSummary(t *testing.T) {
	t.Parallel()
	// Exhaustive URI behavior: TestSanitizeRequestURI and TestRedactPathForSummary_matchesSanitizeRequestURI.
	if got := RedactPathForSummary("/x?token=secret"); got != "/x?token=REDACTED" {
		t.Fatalf("RedactPathForSummary=%q", got)
	}
}

func TestExecEventJSON(t *testing.T) {
	ev := ExecEvent{
		Type: "exec", TS: "2026-01-01T00:00:00Z", Seq: 7,
		PID: 1000, TGID: 1000, ThreadID: 1001, Comm: "bash",
		Exe: "/bin/bash",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"thread_id":1001`)) || !bytes.Contains(b, []byte(`"tgid":1000`)) {
		t.Fatalf("missing fields: %s", b)
	}
	if !bytes.Contains(b, []byte(`"exe":"/bin/bash"`)) {
		t.Fatalf("missing exe: %s", b)
	}
}

func TestIOUringTLSEventJSONLRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("full confidence — SNI populated, peek_failed omitted", func(t *testing.T) {
		ev := IOUringTLSEvent{
			Type: "io_uring_tls", TS: "2026-05-20T12:00:00Z", Seq: 17,
			PID: 4242, TGID: 4242, ThreadID: 4242,
			Comm:       "curl",
			Op:         "send",
			SNI:        "example.com",
			Confidence: "full",
			Note:       "io_uring SQE buffer peek (enhanced profile)",
		}
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		// Confidence is always present (no omitempty); SNI is present when set.
		if !bytes.Contains(b, []byte(`"confidence":"full"`)) {
			t.Errorf("confidence missing: %s", b)
		}
		if !bytes.Contains(b, []byte(`"sni":"example.com"`)) {
			t.Errorf("sni missing: %s", b)
		}
		if bytes.Contains(b, []byte(`"peek_failed"`)) {
			t.Errorf("peek_failed should be omitted when false: %s", b)
		}

		var got IOUringTLSEvent
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != ev {
			t.Fatalf("round-trip mismatch:\n got  %#v\n want %#v", got, ev)
		}
		if EventType(b) != "io_uring_tls" {
			t.Fatalf("EventType=%q want io_uring_tls", EventType(b))
		}
	})

	t.Run("peek_failed — SNI empty, confidence unknown", func(t *testing.T) {
		ev := IOUringTLSEvent{
			Type: "io_uring_tls", TS: "2026-05-20T12:00:01Z", Seq: 18,
			PID: 4242, Comm: "curl",
			Op:         "sendmsg",
			Confidence: "unknown",
			PeekFailed: true,
		}
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Contains(b, []byte(`"peek_failed":true`)) {
			t.Errorf("peek_failed=true missing: %s", b)
		}
		if bytes.Contains(b, []byte(`"sni"`)) {
			t.Errorf("sni should be omitted when empty: %s", b)
		}
		if !bytes.Contains(b, []byte(`"confidence":"unknown"`)) {
			t.Errorf("confidence missing: %s", b)
		}
	})

	t.Run("partial confidence — magic matched but no SNI", func(t *testing.T) {
		ev := IOUringTLSEvent{
			Type: "io_uring_tls", TS: "2026-05-20T12:00:02Z", Seq: 19,
			PID: 4242, Comm: "myproc",
			Op:         "send",
			Confidence: "partial",
			DstIP:      "10.0.0.5",
			DstPort:    443,
		}
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Contains(b, []byte(`"confidence":"partial"`)) {
			t.Errorf("confidence missing: %s", b)
		}
		if !bytes.Contains(b, []byte(`"dst_ip":"10.0.0.5"`)) {
			t.Errorf("dst_ip missing: %s", b)
		}
		if !bytes.Contains(b, []byte(`"dst_port":443`)) {
			t.Errorf("dst_port missing: %s", b)
		}
	})
}

func TestProcForkEventJSONLRoundTrip(t *testing.T) {
	t.Parallel()
	line := `{"type":"proc_fork","ts":"2026-04-11T00:00:00Z","seq":7,"parent_pid":1,"child_pid":42,"parent_comm":"bash","child_comm":"true","note":"best-effort tgid"}` + "\n"
	if got := EventType([]byte(line)); got != "proc_fork" {
		t.Fatalf("EventType=%q", got)
	}
}

func TestMetaCapabilitiesJSON(t *testing.T) {
	t.Parallel()
	raw := `{"type":"meta","schema_version":2,"ts":"t","agent_version":"v","kernel_release":"k","github":{},"bpf":[],"capabilities":{"proc_tree":true}}` + "\n"
	var m MetaEvent
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if !m.Capabilities["proc_tree"] {
		t.Fatalf("capabilities: %#v", m.Capabilities)
	}
}

func TestMetaJSONRoundTrip(t *testing.T) {
	m := MetaEvent{
		Type:          "meta",
		SchemaVersion: SchemaVersion,
		TS:            "2026-01-01T00:00:00Z",
		AgentVersion:  "test",
		KernelRelease: "6.0.0",
		GitHub:        MetaGitHub{Repository: "o/r"},
		BPF:           []BPFStatus{{Name: "tcp", OK: true}},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out MetaEvent
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Type != "meta" || out.SchemaVersion != SchemaVersion || !out.BPF[0].OK {
		t.Fatalf("%+v", out)
	}
}

func TestDenyEventJSON(t *testing.T) {
	ev := DenyEvent{
		Type:     "deny",
		TS:       "2026-01-01T00:00:00Z",
		Seq:      11,
		PID:      2000,
		TGID:     2000,
		ThreadID: 2001,
		Comm:     "curl",
		Protocol: "tcp",
		Dst:      "1.2.3.4",
		Dport:    443,
		Reason:   "dst_not_allowlisted",
		Mode:     "defend",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		`"type":"deny"`,
		`"ts":"2026-01-01T00:00:00Z"`,
		`"seq":11`,
		`"pid":2000`,
		`"tgid":2000`,
		`"thread_id":2001`,
		`"comm":"curl"`,
		`"protocol":"tcp"`,
		`"dst":"1.2.3.4"`,
		`"dport":443`,
		`"reason":"dst_not_allowlisted"`,
		`"mode":"defend"`,
	} {
		if !bytes.Contains(b, []byte(needle)) {
			t.Fatalf("missing %s in %s", needle, string(b))
		}
	}
	if got := EventType(b); got != "deny" {
		t.Fatalf("EventType()=%q", got)
	}
}

func TestDenyEventJSON_HookProvenance(t *testing.T) {
	ev := DenyEvent{
		Type:       "deny",
		TS:         "2026-01-01T00:00:00Z",
		Seq:        3,
		PID:        1,
		TGID:       1,
		ThreadID:   2,
		Comm:       "curl",
		Protocol:   "tcp",
		Dst:        "10.0.0.1",
		Dport:      443,
		Reason:     "dst_not_allowlisted",
		Mode:       "defend",
		HookFamily: "cgroup",
		MatchKind:  "dns_cache",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{`"hook_family":"cgroup"`, `"match_kind":"dns_cache"`} {
		if !bytes.Contains(b, []byte(needle)) {
			t.Fatalf("missing %s in %s", needle, string(b))
		}
	}
}

func TestFSEvent_RoundTrip(t *testing.T) {
	t.Parallel()
	ev := FSEvent{
		Type: "fs_event", TS: "2026-01-01T00:00:00Z", Seq: 5,
		PID: 10, TGID: 10, ThreadID: 11, Comm: "bash",
		Op: "create", Path: "/tmp/test.txt",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if et := EventType(b); et != "fs_event" {
		t.Fatalf("EventType=%q want fs_event", et)
	}
	if bytes.Contains(b, []byte(`"note"`)) {
		t.Fatalf("omitempty note should be absent in JSON, got %s", b)
	}
	var got FSEvent
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != "fs_event" || got.Seq != 5 || got.PID != 10 || got.Comm != "bash" ||
		got.Op != "create" || got.Path != "/tmp/test.txt" {
		t.Fatalf("got %+v", got)
	}
}
