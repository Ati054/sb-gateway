[CmdletBinding()]
param(
    [string]$OutputDirectory = "dist/public-source",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$package = Get-Content -Raw -LiteralPath (Join-Path $projectRoot "package.json") | ConvertFrom-Json
$version = [string]$package.version
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw "package.json does not contain a stable release version."
}

Push-Location -LiteralPath $projectRoot
try {
    & git diff --quiet --exit-code
    if ($LASTEXITCODE -ne 0) { throw "Commit tracked changes before preparing the public repository." }
    & git diff --cached --quiet --exit-code
    if ($LASTEXITCODE -ne 0) { throw "Commit staged changes before preparing the public repository." }

    $exportScript = Join-Path $PSScriptRoot "export-public-source.ps1"
    & $exportScript -OutputDirectory $OutputDirectory -Force:$Force

    $outputRoot = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
        [System.IO.Path]::GetFullPath($OutputDirectory)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
    }
    $repositoryRoot = Join-Path $outputRoot "sb-gateway-$version-source"

    $userName = (& git config user.name).Trim()
    $userEmail = (& git config user.email).Trim()
    if ([string]::IsNullOrWhiteSpace($userName) -or [string]::IsNullOrWhiteSpace($userEmail)) {
        throw "Configure git user.name and user.email before preparing the public repository."
    }

    & git -C $repositoryRoot init --initial-branch=main
    if ($LASTEXITCODE -ne 0) { throw "git init failed for the public repository." }
    & git -C $repositoryRoot add --all
    if ($LASTEXITCODE -ne 0) { throw "git add failed for the public repository." }
    & git -C $repositoryRoot commit -m "release: SB Gateway $version"
    if ($LASTEXITCODE -ne 0) { throw "git commit failed for the public repository." }
    & git -C $repositoryRoot tag -a "v$version" -m "SB Gateway $version"
    if ($LASTEXITCODE -ne 0) { throw "git tag failed for the public repository." }

    $commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    Write-Output "PUBLIC_REPOSITORY=$repositoryRoot"
    Write-Output "PUBLIC_BRANCH=main"
    Write-Output "PUBLIC_TAG=v$version"
    Write-Output "PUBLIC_COMMIT=$commit"
} finally {
    Pop-Location
}
