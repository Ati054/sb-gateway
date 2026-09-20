[CmdletBinding()]
param(
    [string]$RouterOSDirectory = "dist/routeros",
    [string]$PublicSourceDirectory = "dist/public-source",
    [string]$OutputDirectory = "dist/github-release",
    [switch]$SkipWorkspaceCleanup,
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

function Resolve-ProjectPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
}

function Remove-ReleasePath([string]$Path, [string]$AllowedRoot) {
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    if (-not $resolvedPath.StartsWith($resolvedRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the release output directory: $resolvedPath"
    }
    if (Test-Path -LiteralPath $resolvedPath) {
        Remove-Item -LiteralPath $resolvedPath -Recurse -Force
    }
}

$packageCompleted = $false
Push-Location -LiteralPath $projectRoot
try {
    & git diff --quiet --exit-code
    if ($LASTEXITCODE -ne 0) { throw "Commit tracked changes before packaging the GitHub release." }
    & git diff --cached --quiet --exit-code
    if ($LASTEXITCODE -ne 0) { throw "Commit staged changes before packaging the GitHub release." }

    $routerOSRoot = Resolve-ProjectPath $RouterOSDirectory
    $publicSourceRoot = Resolve-ProjectPath $PublicSourceDirectory
    $outputRoot = Resolve-ProjectPath $OutputDirectory
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

    $archiveName = "sb-gateway-$version-linux-arm64.tar"
    $archivePath = Join-Path $routerOSRoot $archiveName
    $archiveChecksumPath = "$archivePath.sha256"
    $manifestPath = Join-Path $routerOSRoot "sb-gateway-$version-linux-arm64.manifest.json"
    $routerOSScripts = Join-Path $routerOSRoot "routeros"
    $sourceArchivePath = Join-Path $publicSourceRoot "sb-gateway-$version-source.zip"
    foreach ($requiredPath in @($archivePath, $archiveChecksumPath, $manifestPath, $routerOSScripts, $sourceArchivePath)) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "Missing release input: $requiredPath"
        }
    }

    $archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    $declaredArchiveHash = ((Get-Content -Raw -LiteralPath $archiveChecksumPath).Trim() -split '\s+')[0].ToLowerInvariant()
    if ($archiveHash -ne $declaredArchiveHash) {
        throw "The container archive does not match its checksum file."
    }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ([string]$manifest.version -ne $version -or [string]$manifest.platform -ne "linux/arm64" -or [string]$manifest.sha256 -ne $archiveHash) {
        throw "The image manifest does not match the release archive."
    }

    $bundleName = "sb-gateway-$version-routeros-bundle.zip"
    $bundlePath = Join-Path $outputRoot $bundleName
    $stagingRoot = Join-Path $outputRoot ".bundle-staging"
    foreach ($target in @($bundlePath, "$bundlePath.sha256", (Join-Path $outputRoot $archiveName), (Join-Path $outputRoot "$archiveName.sha256"), (Join-Path $outputRoot ([System.IO.Path]::GetFileName($manifestPath))), (Join-Path $outputRoot ([System.IO.Path]::GetFileName($sourceArchivePath))), (Join-Path $outputRoot ([System.IO.Path]::GetFileName($sourceArchivePath) + ".sha256")), (Join-Path $outputRoot "RELEASE-NOTES.md"), (Join-Path $outputRoot "SHA256SUMS"), $stagingRoot)) {
        if (Test-Path -LiteralPath $target) {
            if (-not $Force) { throw "Release output already exists; use -Force to replace it: $target" }
            Remove-ReleasePath $target $outputRoot
        }
    }

    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    Copy-Item -LiteralPath $archivePath, $archiveChecksumPath, $manifestPath -Destination $stagingRoot
    Copy-Item -LiteralPath $routerOSScripts -Destination (Join-Path $stagingRoot "routeros") -Recurse
    Copy-Item -LiteralPath (Join-Path $projectRoot "docs/INSTALL.md") -Destination $stagingRoot
    Copy-Item -LiteralPath (Join-Path $projectRoot "docs/INSTALL-RU.md") -Destination $stagingRoot
    Copy-Item -LiteralPath (Join-Path $projectRoot "LICENSE") -Destination $stagingRoot
    Compress-Archive -Path (Join-Path $stagingRoot "*") -DestinationPath $bundlePath -CompressionLevel Optimal
    Remove-ReleasePath $stagingRoot $outputRoot

    Copy-Item -LiteralPath $archivePath, $archiveChecksumPath, $manifestPath, $sourceArchivePath -Destination $outputRoot
    Copy-Item -LiteralPath (Join-Path $projectRoot "docs/releases/$version.md") -Destination (Join-Path $outputRoot "RELEASE-NOTES.md")

    $bundleHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $bundlePath).Hash.ToLowerInvariant()
    $sourceCopy = Join-Path $outputRoot ([System.IO.Path]::GetFileName($sourceArchivePath))
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceCopy).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$bundlePath.sha256", "$bundleHash  $bundleName`n", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText("$sourceCopy.sha256", "$sourceHash  $([System.IO.Path]::GetFileName($sourceCopy))`n", [System.Text.UTF8Encoding]::new($false))

    $checksumTargets = @(
        $bundlePath,
        (Join-Path $outputRoot $archiveName),
        (Join-Path $outputRoot ([System.IO.Path]::GetFileName($manifestPath))),
        $sourceCopy,
        (Join-Path $outputRoot "RELEASE-NOTES.md")
    )
    $checksumLines = foreach ($target in $checksumTargets) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
        "$hash  $([System.IO.Path]::GetFileName($target))"
    }
    [System.IO.File]::WriteAllLines((Join-Path $outputRoot "SHA256SUMS"), $checksumLines, [System.Text.UTF8Encoding]::new($false))

    Write-Output "GITHUB_RELEASE_ASSETS=$outputRoot"
    Write-Output "ROUTEROS_BUNDLE=$bundlePath"
    Write-Output "ROUTEROS_BUNDLE_SHA256=$bundleHash"
    Write-Output "PUBLIC_SOURCE_SHA256=$sourceHash"
    $packageCompleted = $true
} finally {
    Pop-Location
}

if ($packageCompleted -and -not $SkipWorkspaceCleanup) {
    & (Join-Path $PSScriptRoot "clean-local-build-artifacts.ps1") -PublicSourceDirectory $PublicSourceDirectory
}
