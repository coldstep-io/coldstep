#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ImageTag = if ($env:IMAGE_TAG) { $env:IMAGE_TAG } else { "coldstep-code-review-mcp:smoke" }

docker build -t $ImageTag (Join-Path $RepoRoot "docker\code-review-assistant")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$py = "import sys; sys.path.insert(0, '/app'); import server; t=server._load_expert_prompt(); assert len(t)>200; assert 'bpf' in t.lower(); cl=server._checklist_for('go',''); assert 'race' in cl.lower() or 'error' in cl.lower(); print('smoke_ok')"
docker run --rm --entrypoint python $ImageTag -c $py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "smoke-code-review-mcp-docker: passed"
