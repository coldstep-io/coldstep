#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ImageTag = if ($env:IMAGE_TAG) { $env:IMAGE_TAG } else { "coldstep-code-review-mcp:smoke" }
$DockerExe = if ($env:DOCKER) { $env:DOCKER } else { "docker" }

& $DockerExe info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "error: '${DockerExe}' daemon is not running or not reachable" -ForegroundColor Red
    exit 1
}

& $DockerExe build -t $ImageTag (Join-Path $RepoRoot "docker\code-review-assistant")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$py = "import sys; sys.path.insert(0, '/app'); import server; t=server._load_expert_prompt(); assert len(t)>200; assert 'bpf' in t.lower(); cl=server._checklist_for('go',''); assert 'race' in cl.lower() or 'error' in cl.lower(); print('smoke_ok')"
& $DockerExe run --rm --entrypoint python $ImageTag -c $py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "smoke-code-review-mcp-docker: passed"
