## Summary

H13 from the v0.3.0 hardening roadmap: detect **Docker-in-Docker (DinD)** at agent startup and surface the visibility gap so operators are not surprised by missing inner-container egress. coldstep observes the outer runner's cgroup namespace; a container started inside a DinD sidecar runs in a separate cgroup namespace whose traffic the BPF hooks here cannot see.

- **New `DetectRunnerEnv()` helper** in `internal/agent/compat_check_linux.go` reuses the existing `readProc1Cgroup` reader and classifies each run as one of three stable strings:
  - `"dind"` — any line in `/proc/1/cgroup` whose path segment contains `"docker"` (case-insensitive). Matches v1 (`12:devices:/docker/...`), v2 (`0::/docker/.../init.scope`), and mixed-hierarchy shapes.
  - `"standard"` — file exists with no docker markers.
  - `"unknown"` — file missing or unreadable.

  The heuristic is intentionally conservative; false negatives are fine (digest box is informational) and false positives are also acceptable for the same reason. A non-Linux stub returns `"unknown"` so cross-platform callers compile.

- **`MetaEvent.RunnerEnv string \`json:"runner_env,omitempty"\`** (new field) carries the value in the startup meta JSONL line. `"standard"` is collapsed to the empty string so the field is omitted entirely on the common case — present-with-value means the heuristic actively classified the run as DinD or unreadable.

- **`DigestInput.RunnerEnv`** mirrors the MetaEvent field; `buildDigestInput` populates it from a new `runStats.runnerEnv` slot set once at agent startup. The detect digest now renders a ⚠️ blockquote above the fold (right after the headline) when the value is `"dind"`:

  > ⚠️ **Docker-in-Docker detected** — inner container traffic not observed by coldstep.

  Other values (`""` / `"standard"` / `"unknown"`) render nothing — the headline verdict is unchanged.

- **README** gains a Docker-in-Docker bullet in the "Limits" section explaining the cgroup-namespace boundary and pointing operators at running the agent **inside** the inner container if its egress must be captured. This complements the existing Coverage Boundaries pointer in SECURITY.md.

## Test plan

- [x] `go test ./internal/agent/... ./internal/report/... ./internal/telemetry/...` clean on Windows
- [x] `bash scripts/check-gofmt.sh` clean
- [x] `bash scripts/check-encoding.sh` clean
- [x] `TestDetectRunnerEnv_DockerCgroup` exercises v1 / v2 / mixed / case-insensitive `/proc/1/cgroup` content
- [x] `TestDetectRunnerEnv_StandardCgroup` exercises typical hosted-runner shapes (root, init.scope, non-docker system slice)
- [x] `TestBuildDetectMarkdown_RunnerEnv_DinDBox` asserts the digest box fires only on `"dind"` and is suppressed for `"standard"` / `"unknown"` / `""`
- [ ] All CI checks pass (Linux integration paths exercise the agent end-to-end)
