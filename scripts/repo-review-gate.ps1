#Requires -Version 5.1
<#
.SYNOPSIS
  Pre-PR gate: Go vet/staticcheck/tests, TypeScript typecheck, dist parity vs esbuild, optional real MCP Docker verify.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/repo-review-gate.ps1

.EXAMPLE
  $env:SKIP_MCP_DOCKER_VERIFY = "1"; powershell -File scripts/repo-review-gate.ps1
#>
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Invoke-Step {
    param([string]$Label, [scriptblock]$Block)
    Write-Host "== $Label =="
    & $Block
    if ($LASTEXITCODE -ne 0) {
        throw "Step failed: $Label (exit $LASTEXITCODE)"
    }
}

Invoke-Step "go vet" { go vet ./... }
Invoke-Step "staticcheck" { staticcheck ./... }
Invoke-Step "go test (-short)" { go test ./... -count=1 -short }

if (Test-Path (Join-Path $RepoRoot "package.json")) {
    Invoke-Step "npm typecheck" { npm run typecheck }
    Invoke-Step "npm build (esbuild)" { npm run build }
    Invoke-Step "dist parity (git status clean under dist/)" {
        # On Windows, CRLF normalization can make `git diff --quiet` lie while status shows M.
        $dirty = @(git status --porcelain dist/) | Where-Object { $_ -match '\S' }
        if ($dirty.Count -gt 0) {
            Write-Host "dist/ differs from HEAD after esbuild - commit rebuilt bundles or sync src (AGENTS.md dist parity)." -ForegroundColor Red
            $dirty | ForEach-Object { Write-Host $_ }
            exit 1
        }
    }
}

if ($env:SKIP_MCP_DOCKER_VERIFY -eq "1") {
    Write-Host "== MCP Docker verify skipped (SKIP_MCP_DOCKER_VERIFY=1) =="
} else {
    Invoke-Step "MCP Docker stdio verify" { python (Join-Path $RepoRoot "scripts\verify-mcp-code-review-docker.py") }
}

Write-Host "repo-review-gate: OK" -ForegroundColor Green
