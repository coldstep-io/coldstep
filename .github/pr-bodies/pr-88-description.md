## Summary

This change tightens detect-mode integrity on **coldstep-redteam-ebpf** and removes Node 20 / forced Node 24 mismatch warnings for **upload-artifact**.

## Changes

- **internal/agent/agent_linux.go:** Attach **raw_tp/sys_enter (bpf audit)** only after fork and fs BPF collections finish loading, so Coldstep's own **bpf(2)** bursts during load cannot fill the small audit ringbuf before **readBPFAuditRing** runs (restores **bpftool** JSONL canaries).

- **.github/workflows/coldstep-redteam-ebpf.yml:** Run **apt-get** (runtime tools) before composite **phase: start** so package installs do not exhaust the **fs_event** JSONL cap before the intentional **chmod** probe; add **openssl s_client** TLS probe; longer settle; resolve **bpftool** via **command -v** / **/usr/sbin/bpftool**; pin **actions/upload-artifact@v6**.

- **Other workflows:** **actions/upload-artifact@v4** to **@v6** where used (demo, ci-runner, ci-nightly, supply-chain-attest).

- **README.md / CHANGELOG.md:** Pin table and Unreleased notes.

## Verification

- **coldstep-redteam-ebpf** (push to **dev**): https://github.com/coldstep-io/coldstep/actions/runs/25292478576 -- success

- **coldstep-ci** (**workflow_dispatch** on **dev**, full matrix): https://github.com/coldstep-io/coldstep/actions/runs/25292682376 -- success

## Notes

- Local knowledge vault entry (not in git): **knowledge/reports/2026-05-03-ci-redteam-integrity-canaries-and-gha-node24.md**.
