## Summary

Documents TLS 1.3 Encrypted ClientHello (ECH) as a known SNI extraction limit and surfaces the full set of `tls_sni` caveats in the public docs.

- **`internal/report/digest.go`** — adds an ECH callout to the technical-details fold's `writeKPISemantics`, gated on `TLSTotal > 0` and placed immediately after the existing KTLS offload note (`KTLSOffloadTotal > 0`) and before the io_uring note. The blockquote explains that only the outer (CDN/proxy) SNI is visible when ECH is active, and points operators at DNS HTTPS records / app logs for the true destination.
- **`README.md`** / **`QUICK_START.md`** — new "SNI extraction limits" subsection under the existing TLS / SNI material covering fragmented ClientHello (handled by P3-3 inter-syscall reassembly + iov[1] peek), KTLS offload, ECH, and io_uring bypass.
- **`internal/report/digest_test.go`** — two new tests: one asserts the ECH paragraph renders when `TLSTotal > 0`, the other asserts it is absent when `TLSTotal == 0`.

## Test plan

- [x] `go test ./internal/report/... -count=1` (passes locally on Windows)
- [x] `gofmt -l internal/report/digest.go internal/report/digest_test.go` (no output)
- [x] `bash scripts/check-encoding.sh` (no mojibake)
- [ ] CI (`coldstep-ci.yml`) green on `docs/p7-ech-limits`
