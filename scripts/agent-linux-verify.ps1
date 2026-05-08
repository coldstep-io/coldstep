#Requires -Version 5.1
<#
.SYNOPSIS
    Run scripts/agent-linux-verify.sh via Git Bash (or bash on PATH) on Windows/Linux.

.NOTES
    Docker must be running. Honors env: COLDSTEP_VERIFY_MODE, COLDSTEP_VERIFY_TAIL, COLDSTEP_VERIFY_LOG,
    and COLDSTEP_DOCKER_* (passed through to Docker helper scripts).

.PARAMETER RepoRoot
    Repository root containing scripts/. Default: parent of scripts/.

.PARAMETER VerifyMode
    Sets COLDSTEP_VERIFY_MODE for this run (quick | deep | fast).
#>

param(
    [string] $RepoRoot = "",
    [ValidateSet('', 'quick', 'deep', 'fast')]
    [string] $VerifyMode = ""
)

$ErrorActionPreference = "Stop"

function Get-ResolvedRepoRoot {
    param([string] $candidate)
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    }
    return [System.IO.Path]::GetFullPath($candidate)
}

function Resolve-BashPath {
    foreach ($rel in @('Git\bin\bash.exe', 'Git\usr\bin\bash.exe')) {
        foreach ($r in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if ([string]::IsNullOrWhiteSpace($r)) { continue }
            $p = Join-Path $r $rel
            if (Test-Path -LiteralPath $p) {
                return [System.IO.Path]::GetFullPath($p)
            }
        }
    }
    $localGit = Join-Path $env:LOCALAPPDATA "Programs\Git\bin\bash.exe"
    if (Test-Path -LiteralPath $localGit) {
        return [System.IO.Path]::GetFullPath($localGit)
    }
    foreach ($cmd in @("bash", "bash.exe")) {
        try {
            $g = Get-Command $cmd -ErrorAction SilentlyContinue
            if ($null -ne $g -and $null -ne $g.Source -and (Test-Path -LiteralPath $g.Source)) {
                $src = [System.IO.Path]::GetFullPath($g.Source)
                $lc = $src.ToLowerInvariant()
                if (
                    ($lc.EndsWith("\system32\bash.exe")) -or
                    ($lc.EndsWith("\syswow64\bash.exe")) -or
                    ($lc -like "*\windowsapps\bash.exe")
                ) { continue }
                return $src
            }
        }
        catch {
        }
    }
    return ""
}

$BashExe = Resolve-BashPath

if (-not [string]::IsNullOrWhiteSpace($VerifyMode)) {
    $env:COLDSTEP_VERIFY_MODE = $VerifyMode
}

$RepoRootResolved = Get-ResolvedRepoRoot $RepoRoot
$VerifySh = Join-Path $RepoRootResolved "scripts/agent-linux-verify.sh"
if (-not (Test-Path -LiteralPath $VerifySh)) {
    Write-Error "Missing scripts/agent-linux-verify.sh under RepoRoot: $RepoRootResolved"
    exit 2
}

if ([string]::IsNullOrWhiteSpace($BashExe)) {
    Write-Error @"
Could not find bash.exe.

Install Git for Windows (Git\bin\bash.exe) or ensure bash is on PATH.

Alternatively: python scripts/agent_linux_verify.py [--mode fast]
"@
    exit 127
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker CLI not found on PATH. Install Docker Desktop and ensure docker is usable."
    exit 127
}

Write-Host ("agent-linux-verify.ps1 bash: $BashExe") -ForegroundColor Cyan
Write-Host ("repo root:      $RepoRootResolved") -ForegroundColor Cyan
$m = $env:COLDSTEP_VERIFY_MODE
if (-not $m) { $m = "(deep via script default)" }
Write-Host ("verify mode env: $m") -ForegroundColor Cyan

& $BashExe $VerifySh $RepoRootResolved
exit $LASTEXITCODE
