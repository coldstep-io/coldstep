//go:build linux

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/coldstep-io/coldstep/internal/config"
)

func TestRun_StartupMemlockInitInvoked(t *testing.T) {
	origRemoveMemlockRlimit := removeMemlockRlimit
	t.Cleanup(func() {
		removeMemlockRlimit = origRemoveMemlockRlimit
	})

	called := 0
	removeMemlockRlimit = func() error {
		called++
		return nil
	}

	err := Run(context.Background(), config.Config{Mode: config.ModeEnforce})
	if called != 1 {
		t.Fatalf("removeMemlockRlimit called %d times, want 1", called)
	}
	if err == nil || !strings.Contains(err.Error(), "requires non-empty allowlist") {
		t.Fatalf("expected enforce allowlist startup error after memlock init, got %v", err)
	}
}

func TestRun_StartupMemlockInitErrorPropagates(t *testing.T) {
	origRemoveMemlockRlimit := removeMemlockRlimit
	t.Cleanup(func() {
		removeMemlockRlimit = origRemoveMemlockRlimit
	})

	want := errors.New("setrlimit memlock failed")
	removeMemlockRlimit = func() error { return want }

	err := Run(context.Background(), config.Config{Mode: config.ModeDetect})
	if !errors.Is(err, want) {
		t.Fatalf("expected error to wrap memlock init failure; err=%v", err)
	}
	if !strings.Contains(err.Error(), "init memlock rlimit") {
		t.Fatalf("expected init memlock context in error, got %v", err)
	}
}
