# Brainstorm Visual Companion (local dev)

This directory vendors the **Superpowers brainstorming Visual Companion**: a small Node HTTP server that watches an HTML “screen” directory and serves the newest mockup to your browser, with optional click events written under `state/`.

**Source:** Adapted from the Cursor Superpowers plugin (`skills/brainstorming/scripts/`). Bundled here so this repository can run the same flow **without** depending on a machine-local plugin path.

**Requirements:** **Node.js** on `PATH` (same family as other JS tooling). Used only for **local brainstorming**, not CI or the Coldstep agent.

## Start (from repository root)

```bash
bash public_scripts/brainstorm_visual_companion/start-server.sh --project-dir "$(pwd)"
```

The script prints **JSON** with a `url` (and paths). Open that URL in a browser.

- Session files persist under **`.superpowers/brainstorm/<session-id>/`** (ignored by git — see root `.gitignore`).
- Write new HTML fragments into the session’s **`content/`** directory (see upstream Visual Companion docs in the Superpowers `brainstorming` skill).

### Windows (Git Bash)

Same command from the repo root in Git Bash. If `start-server.sh` is not executable, run:

```bash
chmod +x public_scripts/brainstorm_visual_companion/start-server.sh public_scripts/brainstorm_visual_companion/stop-server.sh
```

Foreground mode (recommended if background servers get reaped):

```bash
bash public_scripts/brainstorm_visual_companion/start-server.sh --project-dir "$(pwd)" --foreground
```

## Stop

```bash
bash public_scripts/brainstorm_visual_companion/stop-server.sh "<session_dir>"
```

Use the session directory printed when the server started (under `.superpowers/brainstorm/…`).

## Relationship to standalone HTML mocks

You can still open a **full-document** mockup (e.g. `*mockup*.html` at the repo root) directly in the browser. Root `.gitignore` keeps those local. The Visual Companion adds **live reload**, **shared frame CSS**, and **selection events** when you follow the fragment workflow described in the skill.
