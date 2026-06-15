# filesystem event probe

**Attack signal:** filesystem permission changes (e.g. making a dropped
payload executable, or restricting a file to hide it).

**Probe:** creates a temp file, runs `chmod 400` on it, then removes it. glibc's
`chmod` is implemented via `fchmodat`, which coldstep's `trace_fs` hook
captures.

**Expected coldstep behavior (enhanced detect profile):** an `fs_event` appears
in `.coldstep-events.jsonl` for the `chmod`. Note the agent caps `fs_event`
output (≈5k lines), so heavy apt/dpkg activity should be done *before* coldstep
starts to avoid exhausting the cap before this canary fires.

Run it standalone:

```bash
bash redteam/fs-event-probe/probe.sh
```
