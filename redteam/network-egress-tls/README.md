# network egress (TLS)

**Attack signal:** outbound TLS connection to an external host (data egress).

**Probe:** connects to an allowlisted host over TLS via `curl` (HTTP/1.1) and
then `openssl s_client`. The two clients fragment the ClientHello differently,
exercising both of coldstep's SNI-sniff paths. Pass a host as the first
argument; defaults to `theclouddj.com` (the host the red-team workflow
allowlists in its `start` step).

**Expected coldstep behavior (detect mode):** an IPv4 `tls` event with the
target SNI appears in `.coldstep-events.jsonl`. In defend mode, the same host
must be on the allowlist or the connection is dropped.

**Requires:** `curl` (and optionally `openssl`).

Run it standalone:

```bash
bash redteam/network-egress-tls/probe.sh theclouddj.com
```
