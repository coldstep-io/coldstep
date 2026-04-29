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
