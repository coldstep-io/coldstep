# exec canary

**Attack signal:** arbitrary process execution inside the CI job.

**Probe:** runs `ls /etc/passwd` and a `bash -c` one-liner that emits the
`redteam-bash-canary` marker.

**Expected coldstep behavior (detect mode):** an `exec` event appears in
`.coldstep-events.jsonl` for the spawned processes. The `bash` invocation is a
mandatory integrity canary — `coldstep assert-integrity` fails the job if no
`exec` event with `comm=bash` is present (anti-blindness gate).

Run it standalone:

```bash
bash redteam/exec-canary/probe.sh
```
