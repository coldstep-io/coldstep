#Requires -Version 5.1
<#
.SYNOPSIS
  Edit a GitHub PR description from a UTF-8 file (avoids PowerShell mangling gh --body "...").

.EXAMPLE
  ./scripts/gh-pr-body.ps1 -Number 88 -BodyFile .github/pr-bodies/pr-88-description.md
#>
param(
    [Parameter(Mandatory)][int] $Number,
    [Parameter(Mandatory)][string] $BodyFile,
    [string] $Repo = "coldstep-io/coldstep"
)

$path = Resolve-Path -LiteralPath $BodyFile
if (-not (Test-Path -LiteralPath $path)) {
    Write-Error "Body file not found: $BodyFile"
    exit 1
}

gh pr edit $Number --repo $Repo --body-file $path
