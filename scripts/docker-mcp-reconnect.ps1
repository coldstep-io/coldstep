#Requires -Version 5.1
<#
.SYNOPSIS
  Re-enable Docker MCP Toolkit wiring after reboot, Docker Desktop reinstall, or clone.

.DESCRIPTION
  - Ensures the `docker` MCP server is enabled (CLI tools in the gateway).
  - Runs `docker mcp client connect cursor` from the repository root (uses .cursor/mcp.json).
  - Runs `docker mcp client connect gordon -g` for system-wide Gordon.

  Prerequisites: Docker Desktop running, `docker` on PATH, Docker MCP CLI (`docker mcp`).

  Run from anywhere:
    pwsh -File scripts/docker-mcp-reconnect.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

Write-Host "Checking Docker CLI..."
& docker version *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Error "Docker CLI failed. Start Docker Desktop and retry."
}

Write-Host "Enabling docker MCP server (idempotent)..."
& docker mcp server enable docker
if ($LASTEXITCODE -ne 0) {
  Write-Error "docker mcp server enable docker failed (exit $LASTEXITCODE)."
}

Write-Host "Connecting Cursor for this repo: $RepoRoot"
& docker mcp client connect cursor
if ($LASTEXITCODE -ne 0) {
  Write-Error "docker mcp client connect cursor failed (exit $LASTEXITCODE)."
}

Write-Host "Connecting Gordon (global)..."
& docker mcp client connect gordon -g
if ($LASTEXITCODE -ne 0) {
  Write-Error "docker mcp client connect gordon -g failed (exit $LASTEXITCODE). If Gordon is not installed, skip or install Docker Gordon."
}

Write-Host ""
Write-Host "--- docker mcp client ls (project) ---"
& docker mcp client ls
Write-Host ""
Write-Host "--- docker mcp server ls ---"
& docker mcp server ls

Write-Host ""
Write-Host "Done. Restart Cursor and/or Docker Desktop (Gordon) if MCP tools do not appear yet."
