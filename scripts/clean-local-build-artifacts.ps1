[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$PublicSourceDirectory = "dist/public-source",
    [switch]$IncludeDependencies
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)

function Resolve-ProjectPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
}

function Assert-ProjectChildPath([string]$Path) {
    $resolved = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    if (-not $resolved.StartsWith($projectRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a path outside the project workspace: $resolved"
    }
    return $resolved
}

function Get-DirectoryBytes([string]$Path) {
    $measurement = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum
    if ($null -eq $measurement) { return [int64]0 }
    if ($null -eq $measurement.Sum) { return [int64]0 }
    return [int64]$measurement.Sum
}

$targets = [System.Collections.Generic.List[string]]::new()
foreach ($relativePath in @(
    ".tmp",
    "output",
    ".next",
    ".npm-cache",
    ".cache-release",
    "coverage",
    "out",
    ".vinext",
    ".browser-test",
    ".playwright-cli",
    ".playwright-daemon"
)) {
    $targets.Add((Resolve-ProjectPath $relativePath))
}

$publicSourceRoot = Assert-ProjectChildPath (Resolve-ProjectPath $PublicSourceDirectory)
if (Test-Path -LiteralPath $publicSourceRoot -PathType Container) {
    foreach ($repository in Get-ChildItem -LiteralPath $publicSourceRoot -Directory -Filter "sb-gateway-*-source") {
        foreach ($generatedName in @("node_modules", ".next", "out", ".vinext", ".npm-cache", ".tmp")) {
            $targets.Add((Join-Path $repository.FullName $generatedName))
        }
    }
}

if ($IncludeDependencies) {
    $targets.Add((Resolve-ProjectPath "node_modules"))
}

$removedBytes = [int64]0
$removedCount = 0
foreach ($candidate in $targets | Sort-Object -Unique) {
    $target = Assert-ProjectChildPath $candidate
    if (-not (Test-Path -LiteralPath $target)) { continue }

    $bytes = Get-DirectoryBytes $target
    if ($PSCmdlet.ShouldProcess($target, "Remove reproducible build artifacts")) {
        Remove-Item -LiteralPath $target -Recurse -Force
        $removedBytes += $bytes
        $removedCount++
        Write-Output "CLEANED=$target"
    }
}

Write-Output "CLEANED_PATHS=$removedCount"
Write-Output "CLEANED_BYTES=$removedBytes"
