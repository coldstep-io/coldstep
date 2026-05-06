# Code-review MCP (Docker)

Stdio MCP server: expert rubric and checklists ship **inside the image**. **No API keys** and **no outbound HTTP** from the container. Optional offline docs: mount read-only at `/data/docs`.

## Build

```bash
docker build -t coldstep-code-review-mcp:local docker/code-review-assistant
```

## Pin by digest (repeatability)

After pushing to a registry:

```bash
docker pull ghcr.io/coldstep-io/coldstep-code-review-mcp:v1
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/coldstep-io/coldstep-code-review-mcp:v1
```

Use `image@sha256:...` in runbooks and MCP config so everyone runs identical prompt bytes.

## Run (stdio for MCP clients)

Use `-i` so Docker keeps stdin open for MCP stdio.

```bash
docker run --rm -i coldstep-code-review-mcp:local
```

Optional corpus mount (read-only):

```bash
docker run --rm -i -v /path/to/rfc-mirror:/data/docs:ro coldstep-code-review-mcp:local
```

### Windows (PowerShell)

Use forward slashes or escaped backslashes for the host path:

```powershell
docker run --rm -i -v C:/local/rfc-mirror:/data/docs:ro coldstep-code-review-mcp:local
```

## Cursor MCP (`mcp.json`)

Point `command` at Docker; args must include `run`, `--rm`, `-i`, image reference.

**Linux/macOS/Git Bash example:**

```json
{
  "mcpServers": {
    "code-review-expert": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "coldstep-code-review-mcp:local"
      ]
    }
  }
}
```

**With offline docs mount (adjust host path):**

```json
{
  "mcpServers": {
    "code-review-expert": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v",
        "/path/to/docs:/data/docs:ro",
        "coldstep-code-review-mcp:local"
      ]
    }
  }
}
```

**Windows note:** Prefer `docker` on `PATH` from Docker Desktop. Volume syntax: `"C:\\local\\docs:/data/docs:ro"` or Git Bash-style `/c/local/docs:/data/docs:ro`.

## Rubric workflow

1. Call `get_expert_system_prompt` or `prepare_review_packet` **before** debating code.
2. Use `sequential_review_thought` to keep multi-step reasoning structured.
3. Use `review_checklist` with `language` set (e.g. `go`, `c`, `bpf`, `github_actions`).

## Tools

| Tool | Purpose |
|------|---------|
| `get_expert_system_prompt` | Full reviewer system prompt from the image |
| `prepare_review_packet` | Prompt + checklist + optional focus + code blob |
| `review_checklist` | Short domain checklist string |
| `sequential_review_thought` | JSON chain-of-thought step recorder |
