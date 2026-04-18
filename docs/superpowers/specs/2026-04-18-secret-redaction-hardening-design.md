# Design: Secret / API-key redaction hardening (Coldstep-first)

**Date:** 2026-04-18  
**Status:** Draft for review  
**Brainstorming choices:** Scope **C** (Coldstep-first + short general appendix); deliverable **2** (code hardening + tests + wired paths).

## 1. Problem

Coldstep persists **traffic and HTTP-shaped telemetry** (JSONL, digest tables, job summaries). **Credential-like material** must not appear verbatim in those outputs: query tokens, Bearer strings, JWT-shaped blobs, and provider-specific API key patterns already partially handled in **`internal/telemetry/sanitize_request_uri.go`**.

Gaps risk **new leak paths** (unsanitized fields) or **new secret shapes** not covered by existing regexes/query-key allowlists.

## 2. Goals

1. **Reduce leakage** on persisted, diffable surfaces without destroying **host/path/query-structure** usefulness for egress diffing (**AGENTS.md** alignment).
2. Keep logic **centralized** in **`telemetry`** sanitizers unless a call site truly needs a different contract.
3. Add **tests** proving each new rule and each wired high-risk path.
4. Include a **short portable appendix** (operators, CI, headers)—not a second product.

## 3. Non-goals

- Replacing **GitHub Actions** secret masking or **runner** env injection behavior (document only).
- **Structured logging overhaul** across the repo (slog schemas, zap, etc.).
- Redacting **non-credential** PII beyond what OWASP/repo policy already scopes (unless a specific field is shown to carry secrets today).

## 4. Approach

**Hybrid (recommended in brainstorm):**

| Track | Action |
| ----- | ------ |
| **Patterns** | Extend **`redactCredentialPatterns`** and/or **`sensitiveQueryKeys`** only with **narrow, reviewable** rules (named shapes: provider prefixes, JWT/Bearer patterns already established). Avoid “any long base64” heuristics unless justified with false-positive analysis. |
| **Call-site audit** | **Grep-driven**: **`AppendJSONL`**, **`RedactPathForSummary`**, **`SanitizeRequestURI`**, digest row builders (`internal/report`, `internal/agent` HTTP/TLS sections), any **markdown/summary** composition for URLs. Ensure URI-shaped strings go through **`SanitizeRequestURI`** / **`RedactPathForSummary`** before persistence. Fix **proven gaps** only—no speculative edits across unrelated packages. |

## 5. Coldstep architecture (current)

- **`SanitizeRequestURI(raw string)`** — Parses `http(s)://` or path-only URIs; strips/replaces sensitive **query keys**; runs **`redactCredentialPatterns`** on segments and fragments.
- **`RedactPathForSummary`** — Thin path for summaries (delegates to sanitize behavior per existing tests).
- **`redactCredentialPatterns`** — Regex replacements for JWT-like, Bearer, GitHub PAT-shaped, Stripe, AWS access key id patterns.

**Invariant:** Prefer **calling existing exports** over duplicating regexes in **`agent`** or **`report`**.

## 6. Implementation outline (future work—not done in brainstorming)

1. **Audit pass** — Document a short table in the implementation plan: **field / file / sanitizer used / gap?**
2. **Patterns** — Add rules one at a time with **table tests** in **`internal/telemetry/event_test.go`** or **`sanitize_request_uri_test.go`** if split.
3. **Call sites** — Minimal diffs to route leaked strings through **`SanitizeRequestURI`** / **`RedactPathForSummary`**.
4. **Regression** — `go test ./internal/telemetry/...`; agent/report tests if touched; Docker **`go test`** per **AGENTS.md** for merge confidence.

## 7. Testing strategy

- **Unit:** For each new regex/key: positive (redacted), negative control (benign URL unchanged), optional near-miss.
- **Regression:** Existing **`TestSanitizeRequestURI`** / **`TestRedactPathForSummary`** extended; no removal of behavioral guarantees without changelog note.
- **Manual spot-check:** Optional JSONL fixture line after change (local only).

## 8. General appendix (operators)

Brief checklist—details live in **`knowledge/wiki/log-redaction-api-keys-secrets`** (local vault) and OWASP Logging Cheat Sheet stub:

- Never log **`Authorization`**, cookies, or raw **`env`** dumps in CI logs for debugging.
- Prefer **platform masking** for secrets in workflows; avoid **`echo`** of secrets.
- Sanitize **before** SIEM/UI if logs are reused in tickets.

## 9. Success criteria

- [ ] Audit table completed; **no known** JSONL/digest/summary path carries **unsanitized** URI with covered secret shapes.
- [ ] New/changed rules have **tests**; **`go test ./...`** passes in CI/Docker policy.
- [ ] **AGENTS.md** egress guidance remains satisfied: redact auth material; **keep** informative hosts/query keys for diffing.

## 10. Rollout / risk

- **False positives:** New regexes might redact benign strings—mitigate with **tight patterns** and tests with realistic HTTP paths.
- **Behavior change:** Digest/summary strings may differ (more `REDACTED`)—acceptable for security; note in PR for reviewers.

---

**Next step after approval:** Use **writing-plans** to produce an executable task list (audit grep list, ordered edits, verification commands). **No code changes** until that plan is executed in a separate session unless explicitly requested.
