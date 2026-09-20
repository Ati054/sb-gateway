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

$releaseDocument = Join-Path $projectRoot "docs/releases/$version.md"
if (-not (Test-Path -LiteralPath $releaseDocument -PathType Leaf)) {
    throw "Missing release document docs/releases/$version.md."
}

Push-Location -LiteralPath $projectRoot
try {
    & git diff --quiet --exit-code
    if ($LASTEXITCODE -ne 0) { throw "Commit tracked changes before exporting public source." }
    & git diff --cached --quiet --exit-code
    if ($LASTEXITCODE -ne 0) { throw "Commit staged changes before exporting public source." }

    $outputRoot = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
        [System.IO.Path]::GetFullPath($OutputDirectory)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
    }
    $sourceRoot = Join-Path $outputRoot "sb-gateway-$version-source"
    $archivePath = Join-Path $outputRoot "sb-gateway-$version-source.zip"
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
    if ((Test-Path -LiteralPath $sourceRoot) -or (Test-Path -LiteralPath $archivePath)) {
        if (-not $Force) { throw "Public source output already exists; use -Force to replace it." }
        if (Test-Path -LiteralPath $sourceRoot) { Remove-Item -LiteralPath $sourceRoot -Recurse -Force }
        if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
    }

    $temporaryArchive = Join-Path $outputRoot ".sb-gateway-$version-source.tmp.zip"
    if (Test-Path -LiteralPath $temporaryArchive) { Remove-Item -LiteralPath $temporaryArchive -Force }
    & git archive --format=zip --output=$temporaryArchive HEAD
    if ($LASTEXITCODE -ne 0) { throw "git archive failed." }
    Expand-Archive -LiteralPath $temporaryArchive -DestinationPath $sourceRoot
    Remove-Item -LiteralPath $temporaryArchive -Force

    $publicReleaseVersions = @($version)
    $publicChangelog = @("# Changelog", "")
    foreach ($publicReleaseVersion in $publicReleaseVersions) {
        $publicReleasePath = Join-Path $sourceRoot "docs/releases/$publicReleaseVersion.md"
        if (-not (Test-Path -LiteralPath $publicReleasePath -PathType Leaf)) {
            throw "Missing public release document docs/releases/$publicReleaseVersion.md."
        }
        $releaseLines = @(Get-Content -Encoding UTF8 -LiteralPath $publicReleasePath)
        if ($releaseLines.Count -eq 0 -or $releaseLines[0] -ne "# SB Gateway $publicReleaseVersion") {
            throw "Release document $publicReleaseVersion has an unexpected title."
        }
        $publicChangelog += @("## $publicReleaseVersion") + $releaseLines[1..($releaseLines.Count - 1)]
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines((Join-Path $sourceRoot "CHANGELOG.md"), $publicChangelog, $utf8NoBom)
    Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'docs/releases') -File | Where-Object {
        $_.Name -ne "$version.md"
    } | Remove-Item -Force

    $forbiddenRoots = @(
        '.agents', '.codex', '.lab', '.openai', 'AGENTS.md', 'CODEX_HANDOFF.md',
        'IMPLEMENTATION_REPORT.md', 'QUATTRO_SERVERS_AUDIT.md',
        'docs/ACCEPTANCE-TESTS.md', 'docs/research', 'templates/xray.smoke.json'
    )
    foreach ($relative in $forbiddenRoots) {
        $target = Join-Path $sourceRoot $relative
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
    }
    foreach ($relative in @(
        'tests/lab-stress-harness.test.mjs',
        'tests/password-persistence.test.mjs',
        'tests/ruleset-domain-audit.test.mjs'
    )) {
        $target = Join-Path $sourceRoot $relative
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    }
    $forbiddenFiles = @(Get-ChildItem -LiteralPath $sourceRoot -File -Recurse | Where-Object {
        $_.Name -match '^\.env|\.(pem|key|p12|pfx)$'
    })
    if ($forbiddenFiles.Count -ne 0) {
        throw "Credential-like files entered the public source export."
    }

    Compress-Archive -Path (Join-Path $sourceRoot '*') -DestinationPath $archivePath
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    Write-Output "PUBLIC_SOURCE=$sourceRoot"
    Write-Output "PUBLIC_SOURCE_ARCHIVE=$archivePath"
    Write-Output "PUBLIC_SOURCE_SHA256=$hash"
} finally {
    Pop-Location
}
