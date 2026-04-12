//go:build linux

package telemetry

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// BuildMeta constructs the opening JSONL record (call once per agent run).
func BuildMeta(agentVer string, bpf []BPFStatus) (MetaEvent, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return MetaEvent{}, err
	}
	kernel := unix.ByteSliceToString(uts.Release[:])

	gh := MetaGitHub{
		Repository: os.Getenv("GITHUB_REPOSITORY"),
		Workflow:   os.Getenv("GITHUB_WORKFLOW"),
		RunID:      os.Getenv("GITHUB_RUN_ID"),
		RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"),
		Job:        os.Getenv("GITHUB_JOB"),
		SHA:        os.Getenv("GITHUB_SHA"),
		Ref:        os.Getenv("GITHUB_REF"),
		Actor:      os.Getenv("GITHUB_ACTOR"),
	}

	return MetaEvent{
		Type:          "meta",
		SchemaVersion: SchemaVersion,
		TS:            time.Now().UTC().Format(time.RFC3339Nano),
		AgentVersion:  strings.TrimSpace(agentVer),
		KernelRelease: kernel,
		GitHub:        gh,
		BPF:           bpf,
	}, nil
}
