package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetenvDefault(t *testing.T) {
	k := "COLDSTEP_GETENV_DEFAULT_PROBE"
	t.Setenv(k, "")
	if getenvDefault(k, "fallback") != "fallback" {
		t.Fatal("empty env")
	}
	t.Setenv(k, "   ")
	if getenvDefault(k, "fallback") != "fallback" {
		t.Fatal("whitespace-only env")
	}
	t.Setenv(k, " ok ")
	if getenvDefault(k, "fallback") != "ok" {
		t.Fatal("trimmed value")
	}
}

func TestRuntimeOS_runnerPreferred(t *testing.T) {
	t.Setenv("RUNNER_OS", "Linux")
	if runtimeOS() != "linux" {
		t.Fatalf("got %q", runtimeOS())
	}
}

func TestReadReady(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ready.json")
	ok, known := readReady(p)
	if ok || known {
		t.Fatal("missing file should be unknown")
	}
	if err := os.WriteFile(p, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, known = readReady(p)
	if !ok || !known {
		t.Fatalf("got ok=%v known=%v", ok, known)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPostPRComment_success(t *testing.T) {
	old := httpNotifyClient
	defer func() { httpNotifyClient = old }()

	httpNotifyClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPost {
				t.Errorf("method %s", req.Method)
			}
			if want := "/repos/acme/demo/issues/7/comments"; req.URL.Path != want {
				t.Errorf("path %s want %s", req.URL.Path, want)
			}
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader("{}")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	dir := t.TempDir()
	eventPath := filepath.Join(dir, "event.json")
	payload := `{"pull_request":{"number":7}}`
	if err := os.WriteFile(eventPath, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_REPOSITORY", "acme/demo")
	t.Setenv("GITHUB_EVENT_PATH", eventPath)

	if err := postPRComment("secret-token", "hello **digest**"); err != nil {
		t.Fatal(err)
	}
}

func TestPostPRComment_skipsWithoutRepo(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "")
	if err := postPRComment("t", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestPostPRComment_skipsWithoutEventPath(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "a/b")
	t.Setenv("GITHUB_EVENT_PATH", "")
	if err := postPRComment("t", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestPostPRComment_eventTooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.json")
	if err := os.WriteFile(p, bytes.Repeat([]byte{'x'}, maxGitHubEventJSONBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_REPOSITORY", "a/b")
	t.Setenv("GITHUB_EVENT_PATH", p)
	if err := postPRComment("t", "b"); err == nil {
		t.Fatal("expected error for oversized event")
	}
}
