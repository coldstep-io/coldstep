# Secret / API-key redaction hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close gaps in persisted telemetry (JSONL, digest markdown, job summaries) so credential-shaped strings in URI/path surfaces are centralized in `telemetry` sanitizers with table-driven tests.

**Architecture:** Extend `internal/telemetry/sanitize_request_uri.go` (`sensitiveQueryKeys`, `redactCredentialPatterns`, `SanitizeRequestURI`). HTTP rows already call `telemetry.RedactPathForSummary` before JSONL/digest from `internal/agent/agent_linux.go`; fix proven gaps only—no duplicated regex in `report`/`agent`.

**Tech stack:** Go 1.24.x (`go.mod`), tests in `internal/telemetry`. CI truth path: GitHub-hosted `ubuntu-latest` (`coldstep-ci.yml` / `coldstep-ci-runner.yml`). Local Linux parity: Docker `golang` image + bind-mount.

---

## Audit table (field → persistence → sanitizer)

| Surface | Field | Source file | Sanitizer before persist? | Gap? |
| -------- | ----- | ----------- | --------------------------- | ---- |
| JSONL `http` | `path` | `internal/agent/agent_linux.go` (`HTTPEvent`, `readHTTPRing`) | Yes — `telemetry.RedactPathForSummary(path)` | **None** (after sanitize hardening) |
| Digest HTTP table | `Path` | Same — `report.HTTPDigestRow` | Same string as JSONL | **None** |
| JSONL `tcp`/`udp`/`tls`/`exec`/… | no raw URL path | `agent_linux.go` | N/A for URI secrets | **None** for this spec |
| Digest markdown cells | HTTP Path | `internal/report/digest.go` (`sanitizeCell` only escapes markdown) | Path must already be redacted upstream | **None** if rows use `sumPath` |
| Relative `foo?token=` strings | N/A for HTTP sniff | `ParseHTTPRequestPrefix` requires leading `/` | Edge: non-HTTP callers of `SanitizeRequestURI` | **Closed** — branch for `?` without `/` or `://` |

**Grep checklist (expected):**

- `RedactPathForSummary` / `SanitizeRequestURI` appear on the HTTP hot path in `agent_linux.go`.
- No second copy of JWT/Bearer/Stripe regex outside `sanitize_request_uri.go`.

---

### Task 1: Baseline verification (read-only)

**Files:** None — commands only.

- [ ] **Step 1:** From repo root, confirm HTTP path uses summary redaction:

```bash
rg -n "RedactPathForSummary|AppendJSONL.*HTTPEvent" internal/agent/agent_linux.go
```

**Expected:** At least one line assigning `sumPath := telemetry.RedactPathForSummary(path)` and `Path: sumPath` on `HTTPEvent`.

- [ ] **Step 2:** Confirm sanitizers stay centralized:

```bash
rg -n "eyJ\[A-Za-z0-9" internal --glob "*.go"
```

**Expected:** No duplicate JWT regex in `internal/` outside `internal/telemetry/sanitize_request_uri.go` (allow matches only in tests if any).

- [ ] **Step 3:** Optional — list `AppendJSONL` call sites:

```bash
rg -n "AppendJSONL" internal/agent/agent_linux.go
```

**Expected:** HTTP block passes already-redacted `Path`.

---

### Task 2: Relative path + query edge case (`SanitizeRequestURI`)

**Files:**

- Modify: `internal/telemetry/sanitize_request_uri.go`
- Test: `internal/telemetry/sanitize_request_uri_test.go`

**Status:** Intended implementation — relative `path?query` without leading `/` parses via `http://_coldstep.invalid/` + input so query keys participate in `sensitiveQueryKeys` handling; output normalizes to a leading `/` on path.

- [ ] **Step 1: Failing test** — Add table row (if not present):

```go
{
	"relative_no_leading_slash_query_redacted",
	"relative?token=still-visible",
	"/relative?token=REDACTED",
},
```

Run:

```bash
go test ./internal/telemetry/... -run TestSanitizeRequestURI/relative_no_leading_slash -count=1
```

**Expected before fix:** FAIL with wrong `got` vs `want`.

- [ ] **Step 2: Implementation** — After `strings.HasPrefix(s, "/")` branch, add:

```go
} else if strings.Contains(s, "?") && !strings.Contains(s, "://") {
	u, err = url.Parse("http://_coldstep.invalid/" + s)
```

(Full function context must match existing `SanitizeRequestURI` structure.)

- [ ] **Step 3: Pass tests**

```bash
go test ./internal/telemetry/... -count=1
```

**Expected:** PASS.

- [ ] **Step 4: Commit** (signed, on `dev` per `AGENTS.md`)

```bash
git add internal/telemetry/sanitize_request_uri.go internal/telemetry/sanitize_request_uri_test.go
git commit -S -m "telemetry: parse relative path+query for sensitive query keys"
```

---

### Task 3: Extend `sensitiveQueryKeys`

**Files:**

- Modify: `internal/telemetry/sanitize_request_uri.go`
- Test: `internal/telemetry/sanitize_request_uri_test.go`

**Status:** Add keys: `auth`, `credential`, `credentials`, `authorization` (map entries only).

- [ ] **Step 1: Tests** — One row per key, e.g.:

```go
{"auth_query_key", "/x?auth=tok", "/x?auth=REDACTED"},
```

- [ ] **Step 2: Implement** — Add keys to `sensitiveQueryKeys` map.

- [ ] **Step 3: Run**

```bash
go test ./internal/telemetry/... -run TestSanitizeRequestURI -count=1
```

**Expected:** PASS.

- [ ] **Step 4: Commit** (signed)

```bash
git commit -S -m "telemetry: redact auth-related query parameter names"
```

---

### Task 4: Provider regex patterns (narrow)

**Files:**

- Modify: `internal/telemetry/sanitize_request_uri.go` (`var` block + `redactCredentialPatterns`)
- Test: `internal/telemetry/sanitize_request_uri_test.go`

**Status:** Add compiled regexes and replacements (order: after existing AWS, same style as Stripe):

```go
openAIProjKeyRE = regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}\b`)
googleAPIKeyRE  = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)
sendGridKeyRE   = regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{30,}\b`)
```

In `redactCredentialPatterns`, after `awsKeyRE`:

```go
s = openAIProjKeyRE.ReplaceAllString(s, redactedCredential)
s = googleAPIKeyRE.ReplaceAllString(s, redactedCredential)
s = sendGridKeyRE.ReplaceAllString(s, redactedCredential)
```

- [ ] **Step 1: Tests** — Table rows:

```go
{
	"openai_proj_key_in_query",
	"/x?k=sk-proj-" + strings.Repeat("a", 24),
	"/x?k=" + redactedCredential,
},
{
	"google_api_key_in_query",
	"/x?k=AIza" + strings.Repeat("0", 35),
	"/x?k=" + redactedCredential,
},
{
	"sendgrid_key_in_query",
	"/x?k=SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43),
	"/x?k=" + redactedCredential,
},
```

- [ ] **Step 2: Implement** — Wire regexes as above.

- [ ] **Step 3:**

```bash
go test ./internal/telemetry/... -count=1
```

**Expected:** PASS.

- [ ] **Step 4: Commit** (signed)

```bash
git commit -S -m "telemetry: redact OpenAI, Google, SendGrid key shapes in URIs"
```

---

### Task 5: Full regression

**Files:** None (commands).

- [ ] **Step 1: Full Go test**

```bash
go test ./... -count=1
```

**Expected:** All packages OK (integration tags may apply on Linux only; match CI).

- [ ] **Step 2: Docker parity (AGENTS.md policy)**

Linux/macOS host with Docker:

```bash
docker run --rm -v "%CD%:/src" -w /src golang:1.24-bookworm go test ./... -count=1
```

PowerShell:

```powershell
docker run --rm -v "${PWD}:/src" -w /src golang:1.24-bookworm go test ./... -count=1
```

**Expected:** Exit code 0.

---

### Task 6 (optional): Slack bot/user tokens

**Files:** Same as Task 4.

**Only if** you accept more `REDACTED` false positives on strings like `xoxb-...` in URLs.

- [ ] **Step 1: Failing test**

```go
{
	"slack_bot_token_in_query",
	"/x?k=xoxb-" + strings.Repeat("1", 16) + "-" + strings.Repeat("a", 12),
	"/x?k=" + redactedCredential,
},
```

- [ ] **Step 2: Regex** (example — tune to real Slack formats):

```go
slackTokenRE = regexp.MustCompile(`\bxox[abopr]-[A-Za-z0-9-]{10,}\b`)
```

Apply in `redactCredentialPatterns` after SendGrid or before JWT (avoid breaking JWT match order if overlapping).

- [ ] **Step 3:** `go test ./internal/telemetry/...` then commit.

---

## Self-review (plan vs spec)

| Spec § | Covered by |
| ------ | ---------- |
| §4 Patterns | Tasks 3–4, optional 6 |
| §4 Call-site audit | Task 1 audit table + grep |
| §7 Unit tests | Each task includes table tests |
| §9 Success criteria | Task 5 regression |
| §8 Appendix (operators) | Out of scope for code — lives in `knowledge/wiki/…` |

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-18-secret-redaction-hardening.md`. Two execution options:**

1. **Subagent-driven (recommended)** — Dispatch a fresh subagent per task; review between tasks.
2. **Inline execution** — Run tasks in this session using `executing-plans`, batch with checkpoints.

**Which approach?**

**Note:** Tasks 2–4 may already be satisfied on branch `dev` (commit message pattern `telemetry: harden URI secret redaction…`). If so, run **Task 1** and **Task 5** only to confirm, then close the spec checklist or open the PR.
