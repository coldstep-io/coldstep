package telemetry

import (
	"encoding/json"
	"os"
	"time"
)

// AppendJSONL appends one JSON object line to path (create if missing).
func AppendJSONL(path string, v any) error {
	if path == "" {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	_, err = f.WriteString("\n")
	return err
}

// Summary is written once at agent shutdown.
type Summary struct {
	Version        int            `json:"version"`
	SchemaVersion  int            `json:"schema_version"`
	Finished       string         `json:"finished"`
	KernelRelease  string         `json:"kernel_release,omitempty"`
	ExecEvents     int            `json:"exec_events"`
	TCPEvents      int            `json:"tcp_events"`
	UDPEvents      int            `json:"udp_events"`
	HTTPEvents     int            `json:"http_events"`
	TLSEvents      int            `json:"tls_events,omitempty"`
	ProcForkEvents int            `json:"proc_fork_events,omitempty"`
	PolicyCounts   map[string]int `json:"policy_counts"`
	BPF            []BPFStatus    `json:"bpf,omitempty"`
}

// WriteSummary writes telemetry summary JSON (overwrites).
func WriteSummary(path string, s Summary) error {
	if path == "" {
		return nil
	}
	if s.Version == 0 {
		s.Version = 2
	}
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
	if s.Finished == "" {
		s.Finished = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if s.PolicyCounts == nil {
		s.PolicyCounts = map[string]int{}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
