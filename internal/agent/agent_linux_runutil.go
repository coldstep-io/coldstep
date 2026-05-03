//go:build linux

package agent

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
	"golang.org/x/sys/unix"
)

func setupLogging(level string) {
	lvl := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}

func writeAgentStatus(path string, ok bool) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// #nosec G301 -- directory must be traversable by the non-root runner user polling readiness.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	payload := map[string]any{"ok": ok, "version": 1}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// GitHub Actions polls this path as the runner user while the agent runs under sudo; 0o600
	// root-owned files are unreadable (EACCES). Payload is non-secret (ok + version only).
	// #nosec G306 -- readiness file intentionally world-readable for runner polling semantics.
	if err := atomicwrite.Bytes(path, b, 0o644); err != nil {
		return err
	}
	slog.Info("agent ready status written", "component", "ready", "path", path, "ok", ok)
	return nil
}

func agentVersionString() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := strings.TrimSpace(bi.Main.Version)
	if v == "" || v == "(devel)" {
		return "devel"
	}
	return v
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}
