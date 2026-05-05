package main

import (
	"errors"
	"testing"
)

func TestRunCLI_usage(t *testing.T) {
	if got := runCLI([]string{"coldstep"}); got != 2 {
		t.Fatalf("runCLI(coldstep)=%d want 2", got)
	}
}

func TestRunCLI_runIgnoresExtraArgs(t *testing.T) {
	prev := agentMain
	defer func() { agentMain = prev }()
	agentMain = func() error { return nil }
	if got := runCLI([]string{"coldstep", "run", "extra"}); got != 0 {
		t.Fatalf("got %d want 0", got)
	}
}

func TestRunCLI_unknown(t *testing.T) {
	if got := runCLI([]string{"coldstep", "nope"}); got != 2 {
		t.Fatalf("got %d want 2", got)
	}
}

func TestRunCLI_runSuccess(t *testing.T) {
	prev := agentMain
	defer func() { agentMain = prev }()
	agentMain = func() error { return nil }
	if got := runCLI([]string{"coldstep", "run"}); got != 0 {
		t.Fatalf("got %d want 0", got)
	}
}

func TestRunCLI_runError(t *testing.T) {
	prev := agentMain
	defer func() { agentMain = prev }()
	agentMain = func() error { return errors.New("boom") }
	if got := runCLI([]string{"coldstep", "run"}); got != 1 {
		t.Fatalf("got %d want 1", got)
	}
}
