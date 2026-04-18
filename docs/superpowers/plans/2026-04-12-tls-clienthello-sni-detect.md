# TLS ClientHello / SNI (IPv4, detect mode) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Emit **detect-only** JSONL rows (new `type`, e.g. `tls`) carrying **Server Name Indication (SNI)** parsed from the first **TLS 1.x/1.3 plaintext ClientHello** on **IPv4 TCP** egress, plus **dst IPv4**, **dport**, **pid/comm**, correlated using a **(tgid, sockfd) → last connect IPv4 tuple** map maintained in the **same** `raw_tp/sys_enter` BPF object as today’s `connect` / `sendto` path—without TLS decryption and without changing **enforce** allowlist semantics in v1.

**Architecture:** Extend [`bpf/trace_connect.bpf.c`](../../bpf/trace_connect.bpf.c) with a small **BPF LRU or HASH map** keyed by `(__u64)tgid<<32 | fd` storing `{daddr,dport}` written on **`connect(2)`** (from `pt_regs.di` = fd + existing sockaddr read from `si`) and deleted on **`close(2)`** (fd from `di`). On **`write(2)`** (`__NR_write` = 1 on x86_64), if a **runtime `BPF_MAP_TYPE_ARRAY` flag** (index 0) enables TLS sniffing, require `count >= 43`, **map hit**, then **`bpf_probe_read_user`** of the first **256–512** bytes; quick-reject unless bytes look like **TLS record** `0x16` (handshake), **version** `0x03 0x01–0x04`, **handshake** `0x01` (ClientHello). If still plausible, reserve a **new ringbuf** (`tls_events`, struct parallel to `http_sniff_event` with a **TLS_PAYLOAD_MAX** cap). **Userspace** (`internal/telemetry`) parses extensions for **extension type `0x0000` (server_name)** with strict length bounds (table-driven tests). **Policy classification** reuses [`policy.Policy.Classify`](../../internal/policy/policy.go) with **SNI hostname string** + destination IP (same as cleartext `Host:` today). **Digest** gains a **TLS/SNI** KPI line + `<details>` table (GFM), **feature-gated** via **`NIGHTSTALKER_FEATURE_GATES=tls_sni=1`** so default CI noise/perf stays unchanged until operators opt in. **Schema:** bump [`telemetry.SchemaVersion`](../../internal/telemetry/event.go) only if you add incompatible JSON fields; prefer additive `type: "tls"` without bump if consumers key off `type` (document in README).

**Tech stack:** C (BPF CO-RE, `clang -Wall -Werror`), `bpf2go`, Go 1.23+, `github.com/cilium/ebpf`, existing `link.AttachRawTracepoint` + `ringbuf.Reader` patterns in [`internal/agent/agent_linux.go`](../../internal/agent/agent_linux.go), golden tests in [`internal/report/digest_test.go`](../../internal/report/digest_test.go), live **`curl -4 https://…`** integration per **AGENTS.md**.

**Implementation status (merged to `main` as of 2026-04-12, PR #2):** Delivered end-to-end (BPF `write`/`close` + maps + `tls_events` ringbuf, `ParseClientHelloSNI`, `TLSEvent`, agent ring reader + gate, digest KPI/section + tests, nightstalker-demo grep, README, `TestRun_TLSClientHelloSNIJSONL`). **Local Docker:** `scripts/docker-ubuntu-test.sh` supports **`NIGHTSTALKER_CONTAINER_BTF_ONLY=1`** (in-container BTF); integration tests **`TestRun_TCPConnectLogged`**, **`TestRun_UDPSendtoLoggedJSONL`**, **`TestRun_HTTPSendtoPort80JSONL`**, and **`TestRun_TLSClientHelloSNIJSONL`** **skip** on kernels whose `uname -r` contains `-microsoft-` (e.g. Docker Desktop WSL2) because `traceconnect` BPF may not verify like **`ubuntu-latest`**—override with **`NIGHTSTALKER_FORCE_SYSCALL_BPF_TESTS=1`**. Checklist steps below remain as written for audit trail.

---

## Expert research notes (resolved for this plan)

1. **Why not uprobes on `SSL_write`?** Libraries differ (OpenSSL, BoringSSL, Go’s crypto/tls). An Action must stay **library-agnostic**; uprobes belong in a separate optional track, not v1 here.

2. **Why not `tcp_sendmsg` kprobe first?** Payload lives behind **`struct msghdr` → `struct iov_iter`**; correct handling spans **`ITER_IOVEC`**, **`ITER_UBUF`**, and kernel-version field layout. It is **doable** but historically **verifier-heavy** and harder to regression-test than syscall-buffer reads. This plan uses **`write(2)` user buffer** once the socket’s IPv4 tuple was observed on **`connect`**, which matches how many CLI tools (`curl`) and runtimes ship the ClientHello.

3. **Plaintext at `write(2)` for TLS:** The **TLS record containing ClientHello is not application-traffic ciphertext**; the peer buffer passed to `write` contains the **TLS record bytes** (starting with **content type** `0x16`). This is the same class of observation as cleartext HTTP sniffing already shipped—**metadata only**, not session keys.

4. **Syscall multiplexer cost:** [`raw_tp/sys_enter`](../../docs/superpowers/specs/2026-04-10-network-hook-notes.md) already runs for **every** syscall; adding a **`write` / `close`** branch only adds work when `id` matches. When TLS sniffing is **disabled** via the BPF config map, the **`write`** branch should **return immediately** after a single byte load from **ARRAY** map (or hoist the map read behind `id == __NR_write`).

5. **`sendmsg` / `writev` gap:** Node, Go, and some stacks may use **`sendmsg`** for the first flight. **v1** documents the gap; **v1.1** adds **`__NR_sendmsg`** (46) with **same** “first chunk” read pattern behind the same map lookup (fd in `di`).

6. **Stale `(tgid,fd)` map entries:** Invalidate on **`close(3)`**. Without **`close`**, a reused fd could briefly label wrong dst—**`close`** hook is **in scope** for v1.

7. **Enforce mode:** Do **not** change cgroup verdict logic in v1; optional later spec may use SNI to refine **domain** allowlisting for HTTPS without DNS A-record pinning.

8. **Alignment:** Implements **Phase 5** sketch in [`2026-04-10-egress-full-stack-monitor-report-ui.md`](2026-04-10-egress-full-stack-monitor-report-ui.md) and the **TLS/SNI** row in the roadmap from the brainstorming thread; does **not** implement FS/LSM tracks in [`2026-04-11-extended-runtime-security-design.md`](../specs/2026-04-11-extended-runtime-security-design.md).

---

## File map

| Path | Responsibility |
|------|----------------|
| [`docs/superpowers/specs/2026-04-10-network-hook-notes.md`](../specs/2026-04-10-network-hook-notes.md) | New subsection: TLS/SNI hook choice, `__NR_write`/`__NR_close`, map invalidation, `sendmsg` follow-up |
| `bpf/trace_tls_write.inc` (create) | `handle_tls_obs_*`: map helpers, `write`/`close` logic, ringbuf submit |
| [`bpf/trace_connect_obs.h`](../../bpf/trace_connect_obs.h) | Shared constants: `__NR_write`, `__NR_close`, `TLS_PAYLOAD_MAX`, `struct tls_sniff_event`, `struct connect_dst_key` / value layout |
| [`bpf/trace_connect.bpf.c`](../../bpf/trace_connect.bpf.c) | `#include` inc, new `SEC` maps: `connect_dst`, `tls_agent_cfg`; call into TLS helper from `handle_raw_sys_enter`; on **successful** IPv4 `connect` parse, **insert map** before/after existing ringbuf submit |
| [`internal/bpf/traceconnect/gen.go`](../../internal/bpf/traceconnect/gen.go) | Unchanged directive path; `go generate` picks up new maps |
| [`internal/telemetry/event.go`](../../internal/telemetry/event.go) | New `TLSEvent` struct JSON tags: `type:"tls"`, `sni`, `dst`, `dport`, `policy`, `note` |
| `internal/telemetry/tls_clienthello.go` (create) | `ParseClientHelloSNI([]byte) (sni string, ok bool)` |
| `internal/telemetry/tls_clienthello_test.go` (create) | Table tests: minimal valid CH + negative cases |
| [`internal/agent/agent_linux.go`](../../internal/agent/agent_linux.go) | After `LoadTraceconnectObjects`, **`Update`** `tls_agent_cfg[0]=1` when `config.FeatureGateEnabled(cfg.FeatureGates,"tls_sni")`; new `tlsRd`, `readTLSRing`, `decodeTLSSniffEvent`; plumb `errCh` |
| [`internal/report/digest.go`](../../internal/report/digest.go) + row types in [`internal/report/detect.go`](../../internal/report/detect.go) (or sibling) | KPI + `<details>` for TLS; sub-note beside KPI |
| [`internal/report/digest_test.go`](../../internal/report/digest_test.go) | Golden needles for TLS section / KPI |
| [`README.md`](../../README.md) | Forensics: “HTTPS shows **tcp** + optional **tls** (SNI) when gate on” |
| [`.github/workflows/nightstalker-demo.yml`](../../.github/workflows/nightstalker-demo.yml) | Optional job or step: `NIGHTSTALKER_FEATURE_GATES=tls_sni=1`, `curl -4 https://example.com`, grep JSONL `"type":"tls"` |

---

### Task 0: Document hook + ABI choices (no behavior change)

**Files:**
- Modify: [`docs/superpowers/specs/2026-04-10-network-hook-notes.md`](../specs/2026-04-10-network-hook-notes.md)

- [x] **Step 1:** Append section **“TLS ClientHello / SNI (detect, IPv4)”** stating: x86_64 **`__NR_write=1`**, **`__NR_close=3`**, **`pt_regs.di`** = fd, **`si`** = user buffer ptr, **`dx`** = length for `write`; **`connect`** fd from **`di`**, sockaddr from **`si`** (existing); map key **64-bit** composite; **`close`** clears key; **`sendmsg`** deferred; perf note on **`write`** branch behind map flag.

- [x] **Step 2:** Commit

```bash
git add docs/superpowers/specs/2026-04-10-network-hook-notes.md
git commit -m "docs(spec): TLS/SNI hook notes for connect+write+close map"
```

---

### Task 1: Userspace TLS ClientHello parser + tests (TDD)

**Files:**
- Create: `internal/telemetry/tls_clienthello.go`
- Create: `internal/telemetry/tls_clienthello_test.go`

- [x] **Step 1:** Add failing tests in `tls_clienthello_test.go`

```go
package telemetry

import (
	"encoding/binary"
	"testing"
)

func TestParseClientHelloSNI_Minimal(t *testing.T) {
	ch := buildSyntheticClientHelloWithSNI("ex.example")
	sni, ok := ParseClientHelloSNI(ch)
	if !ok {
		t.Fatal("expected ok")
	}
	if sni != "ex.example" {
		t.Fatalf("sni=%q", sni)
	}
}

func TestParseClientHelloSNI_RejectsNonHandshake(t *testing.T) {
	buf := []byte{0x17, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00}
	if _, ok := ParseClientHelloSNI(buf); ok {
		t.Fatal("expected false")
	}
}
```

Add **`buildSyntheticClientHelloWithSNI(host string) []byte`** in **`package telemetry`** test file (same package as `ParseClientHelloSNI` so the helper stays unexported). **Drop-in implementation:**

```go
func buildSyntheticClientHelloWithSNI(host string) []byte {
	hb := []byte(host)
	if len(hb) == 0 || len(hb) > 200 {
		return nil
	}
	listLen := 1 + 2 + len(hb)
	extVal := make([]byte, 2+listLen)
	binary.BigEndian.PutUint16(extVal[0:2], uint16(listLen))
	extVal[2] = 0
	binary.BigEndian.PutUint16(extVal[3:5], uint16(len(hb)))
	copy(extVal[5:], hb)
	extBlock := make([]byte, 4+len(extVal))
	binary.BigEndian.PutUint16(extBlock[0:2], 0)
	binary.BigEndian.PutUint16(extBlock[2:4], uint16(len(extVal)))
	copy(extBlock[4:], extVal)

	ch := make([]byte, 0, 256)
	ch = append(ch, 0x03, 0x03)
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0)
	ch = append(ch, 0x00, 0x02, 0x13, 0x01)
	ch = append(ch, 0x01, 0x00)
	extLen := uint16(len(extBlock))
	ch = append(ch, byte(extLen>>8), byte(extLen))
	ch = append(ch, extBlock...)

	chLen := len(ch)
	hs := make([]byte, 0, 4+chLen)
	hs = append(hs, 0x01)
	hs = append(hs, byte(chLen>>16), byte(chLen>>8), byte(chLen))
	hs = append(hs, ch...)

	recBody := hs
	recLen := len(recBody)
	out := make([]byte, 0, 5+recLen)
	out = append(out, 0x16, 0x03, 0x01, byte(recLen>>8), byte(recLen))
	out = append(out, recBody...)
	return out
}
```

- [x] **Step 2:** Run tests (expect compile fail on missing symbol)

```bash
cd c:/dumper_5000
go test ./internal/telemetry -run TestParseClientHelloSNI -count=1
```

Expected: **build failure** (`undefined: telemetry.ParseClientHelloSNI`).

- [x] **Step 3:** Implement **`ParseClientHelloSNI`** + **`scanServerNameList`** in `tls_clienthello.go` (full drop-in below—ClientHello layout: **2** version + **32** random + **1** session id len + session + **2** cipher suite len + suites + **1** compression len + compressions + **2** extensions len + extensions).

```go
package telemetry

import (
	"encoding/binary"
	"strings"
)

// ParseClientHelloSNI extracts the first host_name from a TLS ClientHello in one contiguous buffer.
func ParseClientHelloSNI(b []byte) (sni string, ok bool) {
	if len(b) < 43 {
		return "", false
	}
	if b[0] != 0x16 {
		return "", false
	}
	ver := binary.BigEndian.Uint16(b[1:3])
	if ver < 0x0301 || ver > 0x0304 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 38 || 5+recLen > len(b) {
		return "", false
	}
	hs := b[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", false
	}
	chLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if chLen < 34 || 4+chLen > len(hs) {
		return "", false
	}
	ch := hs[4 : 4+chLen]
	i := 34 // after version + random
	if i >= len(ch) {
		return "", false
	}
	sidLen := int(ch[i])
	i++
	if i+sidLen > len(ch) {
		return "", false
	}
	i += sidLen
	if i+2 > len(ch) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
	i += 2
	if i+csLen > len(ch) {
		return "", false
	}
	i += csLen
	if i >= len(ch) {
		return "", false
	}
	compLen := int(ch[i])
	i++
	if i+compLen > len(ch) {
		return "", false
	}
	i += compLen
	if i+2 > len(ch) {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
	i += 2
	if extLen == 0 || i+extLen > len(ch) {
		return "", false
	}
	return scanServerNameList(ch[i : i+extLen])
}

func scanServerNameList(ext []byte) (string, bool) {
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext[0:2])
		ln := int(binary.BigEndian.Uint16(ext[2:4]))
		if ln < 0 || 4+ln > len(ext) {
			return "", false
		}
		block := ext[4 : 4+ln]
		ext = ext[4+ln:]
		if typ != 0 {
			continue
		}
		if len(block) < 2 {
			return "", false
		}
		listLen := int(binary.BigEndian.Uint16(block[0:2]))
		if listLen < 3 || 2+listLen > len(block) {
			return "", false
		}
		list := block[2 : 2+listLen]
		if len(list) < 3 || list[0] != 0 {
			return "", false
		}
		nameLen := int(binary.BigEndian.Uint16(list[1:3]))
		if nameLen <= 0 || 3+nameLen > len(list) {
			return "", false
		}
		raw := strings.ToLower(strings.TrimSpace(string(list[3 : 3+nameLen])))
		if raw == "" || len(raw) > 255 {
			return "", false
		}
		return raw, true
	}
	return "", false
}
```

- [x] **Step 4:** Run

```bash
gofmt -w internal/telemetry/tls_clienthello.go internal/telemetry/tls_clienthello_test.go
go test ./internal/telemetry -run TestParseClientHelloSNI -count=1
```

Expected: **PASS**

- [x] **Step 5:** Commit

```bash
git add internal/telemetry/tls_clienthello.go internal/telemetry/tls_clienthello_test.go
git commit -m "feat(telemetry): parse ClientHello SNI with tests"
```

---

### Task 2: JSONL `TLSEvent` type

**Files:**
- Modify: [`internal/telemetry/event.go`](../../internal/telemetry/event.go)

- [x] **Step 1:** Add struct (additive)

```go
// TLSEvent is one JSONL record for TLS ClientHello SNI observed on egress (detect).
type TLSEvent struct {
	Type     string `json:"type"` // "tls"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"`
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	SNI      string `json:"sni"`
	Dst      string `json:"dst"`
	Dport    uint16 `json:"dport"`
	Policy   string `json:"policy"`
	Note     string `json:"note,omitempty"`
}
```

- [x] **Step 2:** If you extend `EventType` switch sites, update them (`gofmt`, `go test ./internal/telemetry/...`).

- [x] **Step 3:** Commit

```bash
git add internal/telemetry/event.go
git commit -m "feat(telemetry): add TLSEvent JSONL shape"
```

---

### Task 3: BPF — maps, connect hook map insert, close delete, write sniff

**Files:**
- Modify: [`bpf/trace_connect_obs.h`](../../bpf/trace_connect_obs.h)
- Create: `bpf/trace_tls_write.inc`
- Modify: [`bpf/trace_connect.bpf.c`](../../bpf/trace_connect.bpf.c)

- [x] **Step 1:** Extend `trace_connect_obs.h` with `#ifndef NIGHTSTALKER_NR_WRITE` `#define NIGHTSTALKER_NR_WRITE 1` `#define NIGHTSTALKER_NR_CLOSE 3`, `TLS_PAYLOAD_MAX 256`, and:

```c
struct tls_sniff_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 daddr[4];
	__u8 dport[2];
	__u8 _pad[2];
	__u16 capture_len;
	__u8 payload[TLS_PAYLOAD_MAX];
};
```

- [x] **Step 2:** In `trace_connect.bpf.c`, declare:

```c
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} tls_agent_cfg SEC(".maps");

struct connect4_tuple {
	__u8 daddr[4];
	__u8 dport[2];
	__u8 in_use;
	__u8 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct connect4_tuple);
} connect4_by_tgid_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} tls_events SEC(".maps");
```

- [x] **Step 3:** In `handle_tcp_obs_connect`, after successful sockaddr read, **read fd** from `regs_ptr + offsetof(struct pt_regs, di)` into `__u32 fd`, build `key = ((__u64)tgid) << 32 | fd`, **write** `connect4_tuple` `{daddr,dport,in_use=1}`.

- [x] **Step 4:** Implement `trace_tls_write.inc` with `handle_tls_obs_sys_enter(unsigned long regs_ptr, long id)`:

  - If `id == NIGHTSTALKER_NR_CLOSE`: read `di` fd, delete `connect4_by_tgid_fd` key for current tgid.
  - If `id == NIGHTSTALKER_NR_WRITE`: if `tls_agent_cfg[0] == 0` return 0; read `di`/`si`/`dx`; if `len < 43` return 0; map lookup; if miss return 0; `bpf_probe_read_user` **5 bytes** quick check `0x16 0x03` + handshake `0x01`; on match re-read up to `TLS_PAYLOAD_MAX` into stack then `bpf_ringbuf_reserve` / `submit` same layout pattern as HTTP.

- [x] **Step 5:** From `handle_raw_sys_enter`, call into TLS helper **after** existing branches or integrate `id` dispatch to avoid duplicate reads (keep **connect** logic authoritative for sockaddr).

- [x] **Step 6:** Linux generate + build

Use Git Bash per **AGENTS.md** on Windows hosts:

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && bash scripts/docker-ubuntu-test.sh'
```

Expected: **`go generate` / `go test`** inside Docker completes (integration may skip without `NIGHTSTALKER_INTEGRATION`).

- [x] **Step 7:** Commit BPF + header + inc

```bash
git add bpf/trace_connect_obs.h bpf/trace_tls_write.inc bpf/trace_connect.bpf.c
git commit -m "feat(bpf): tls ClientHello capture via write+connect map"
```

---

### Task 4: Go — ringbuf decode, cfg map enable, `readTLSRing`

**Files:**
- Modify: [`internal/agent/agent_linux.go`](../../internal/agent/agent_linux.go)
- Modify: [`internal/bpf/traceconnect/gen.go`](../../internal/bpf/traceconnect/gen.go) (only if map names require regeneration—normally automatic via `go generate`)

- [x] **Step 1:** Add `decodeTLSSniffEvent` mirroring `decodeHTTPSniffEvent` with `TLS_PAYLOAD_MAX=256`.

- [x] **Step 2:** Extend `startSyscallTrace` signature to return `tlsRd *ringbuf.Reader` **or** add `startTLSRingbufReader`—simplest: extend tuple to `(connRd, udpRd, httpRd, tlsRd, ...)`.

- [x] **Step 3:** After `LoadTraceconnectObjects`, if `config.FeatureGateEnabled(cfg.FeatureGates, "tls_sni")`, `objs.TlsAgentCfg.Update(uint32(0), uint8(1), ebpf.UpdateAny)` (pseudo-API—use correct generated field names from `bpf2go`).

- [x] **Step 4:** Implement `readTLSRing` like `readHTTPRing`, calling `telemetry.ParseClientHelloSNI` on payload; skip ringbuf line if parser returns `!ok`; **`pol.Classify(sni, ip)`** for policy string.

- [x] **Step 5:** Wire `errCh <- readTLSRing(...)` next to `readHTTPRing` in `Run` (same shutdown pattern).

- [x] **Step 6:**

```bash
gofmt -w internal/agent/agent_linux.go
go test ./internal/agent -count=1 -short
```

Expected: **PASS** on dev OS for non-integration packages (Linux full compile in Docker).

- [x] **Step 7:** Commit

```bash
git add internal/agent/agent_linux.go internal/bpf/traceconnect/*.go
git commit -m "feat(agent): tls SNI ringbuf reader and feature gate"
```

---

### Task 5: Digest — KPI + TLS `<details>` + tests

**Files:**
- Modify: [`internal/report/digest.go`](../../internal/report/digest.go)
- Modify: [`internal/report/detect.go`](../../internal/report/detect.go) (or wherever row buffers live)
- Modify: [`internal/report/digest_test.go`](../../internal/report/digest_test.go)

- [x] **Step 1:** Extend `DigestInput` / `rowBuffer` with TLS counters and rows (mirror HTTP pattern: `addTLS`, `tlsEmptyReason` if none).

- [x] **Step 2:** KPI line: when TLS feature visible, append **`<sub>…</sub>`** fragment: **“TLS rows require `tls_sni=1`; they show **SNI** from ClientHello, not decrypted HTTPS.”**

- [x] **Step 3:** Add `TestBuildDetectMarkdown_TLSKPI` asserting substring `tls` / `SNI` / table header.

- [x] **Step 4:**

```bash
gofmt -w internal/report/*.go
go test ./internal/report -count=1
```

Expected: **PASS**

- [x] **Step 5:** Commit

```bash
git add internal/report/digest.go internal/report/detect.go internal/report/digest_test.go
git commit -m "feat(report): digest KPI and section for TLS/SNI"
```

---

### Task 6: Linux integration test — `curl -4 https://`

**Files:**
- Modify: `internal/agent/agent_integration_test.go` (or add `agent_tls_integration_test.go`) with `//go:build integration && linux`

- [x] **Step 1:** New test `TestRun_TLSClientHelloSNIJSONL` — start agent with **`NIGHTSTALKER_FEATURE_GATES=tls_sni=1`**, events path under `t.TempDir()`, run shell `curl -fsS --max-time 5 -4 https://example.com >/dev/null` (or `1.1.1.1:443` if you prefer IP-only—**SNI still sends** `example.com` via `--resolve`):

Use:

```bash
curl -fsS --max-time 5 -4 https://example.com -o /dev/null
```

- [x] **Step 2:** After shutdown, scan JSONL for `"type":"tls"` and substring **`example.com`** in sni field.

- [x] **Step 3:** Skip if `curl` missing (same pattern as other integration tests).

- [x] **Step 4:** Run in Docker with integration:

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && NIGHTSTALKER_INTEGRATION=1 bash scripts/docker-ubuntu-test.sh'
```

Expected: **integration PASS** on environment with BPF + network.

- [x] **Step 5:** Commit

```bash
git add internal/agent/agent_*integration_test.go
git commit -m "test(agent): integration for TLS SNI via curl https"
```

---

### Task 7: nightstalker-demo visibility (optional but recommended)

**Files:**
- Modify: [`.github/workflows/nightstalker-demo.yml`](../../.github/workflows/nightstalker-demo.yml)

- [x] **Step 1:** In detect job, add **one** step with `NIGHTSTALKER_FEATURE_GATES: tls_sni=1`, run `curl -4 …`, then `grep` JSONL for `"type":"tls"` (or jq if already present).

- [x] **Step 2:** Push branch; confirm workflow green on GitHub.

- [x] **Step 3:** Commit

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): assert tls SNI jsonl when feature gate on"
```

---

### Task 8: README forensics + schema note

**Files:**
- Modify: [`README.md`](../../README.md)

- [x] **Step 1:** Document **`tls_sni=1`**, JSONL `type:tls`, and **cleartext-vs-HTTPS** distinction (keep consistent with existing HTTP paragraph).

- [x] **Step 2:** Commit

```bash
git add README.md
git commit -m "docs(readme): TLS/SNI telemetry semantics"
```

---

## Plan self-review (checklist)

| Spec / research item | Task coverage |
|---------------------|---------------|
| Phase 5 TLS row (full-stack plan) | Tasks 1–8 |
| No TLS decrypt | Research § + README |
| IPv4 only | Same as connect path |
| Feature gate default off | Task 4–7 |
| `sendmsg` gap | Task 0 doc + README “known gap” |
| Enforce unchanged v1 | Research §7 |
| Honest perf / syscall note | Task 0 + hook-notes |
| Tests (unit + integration + nightstalker-demo) | Tasks 1, 5, 6, 7 |

**Placeholder scan:** None—`ParseClientHelloSNI` in Task 3 is intended to compile as-is; extend tests with captured **real** ClientHello blobs if edge cases appear (GREASE, padding extension order).

---

**Plan complete and saved to** `docs/superpowers/plans/2026-04-12-tls-clienthello-sni-detect.md`.

**Execution:** Implemented inline (**executing-plans**) on branch `feat/tls-clienthello-sni`. For future similar work, prefer **superpowers:subagent-driven-development** when subagents are available. Merge via PR after **`ubuntu-latest`** CI is green.
