# UDP / DNS canary

**Attack signal:** DNS exfiltration / unexpected UDP egress.

**Probe:** `dig @8.8.8.8 google.com` — a DNS query to a public resolver.

**Expected coldstep behavior (detect mode):** a UDP egress event (and DNS
telemetry under the enhanced profile) is recorded in `.coldstep-events.jsonl`.
The probe is best-effort (`|| true`) — the outbound attempt is what matters,
not whether the resolver answers.

**Requires:** `dig` (Debian/Ubuntu package `dnsutils`).

Run it standalone:

```bash
bash redteam/udp-dns-canary/probe.sh
```
