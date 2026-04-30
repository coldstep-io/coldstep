# Cursor agent skills (Coldstep)

Canonical copies live **here** (tracked). Cursor loads skills from **`.cursor/skills/`** by default, which is **gitignored** in this repo — after clone, symlink or copy:

```powershell
# Windows (PowerShell, repo root) — example junction into Cursor skills folder
New-Item -ItemType Junction -Path ".cursor\skills\coldstep-detect-track" -Target "$PWD\skills\coldstep-detect-track" -Force
New-Item -ItemType Junction -Path ".cursor\skills\coldstep-defend-track" -Target "$PWD\skills\coldstep-defend-track" -Force
```

Or copy the `SKILL.md` trees manually into `.cursor/skills/`.

| Skill | Path |
| ----- | ---- |
| Detect track manager | [coldstep-detect-track/SKILL.md](coldstep-detect-track/SKILL.md) |
| Defend track manager | [coldstep-defend-track/SKILL.md](coldstep-defend-track/SKILL.md) |

Plans (executable backlog):

| Plan | Path |
| ---- | ---- |
| Detect track | [../plans/2026-04-29-coldstep-detect-track.md](../plans/2026-04-29-coldstep-detect-track.md) |
| Defend track | [../plans/2026-04-29-coldstep-defend-track.md](../plans/2026-04-29-coldstep-defend-track.md) |
| Drop `enforce` alias (breaking) | [../plans/2026-04-29-drop-enforce-alias-approach-1.md](../plans/2026-04-29-drop-enforce-alias-approach-1.md) |

Knowledge vault (local second brain): hub [**track-skills-research-loop**](../knowledge/wiki/track-skills-research-loop.md) — not committed to Git.
