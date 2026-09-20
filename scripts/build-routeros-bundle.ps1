[CmdletBinding()]
param(
    [ValidateSet("auto", "docker", "podman")]
    [string]$Engine = "auto",
    [string]$Builder = "",
    [string]$ImageTag = "",
    [string]$OutputDirectory = "dist/routeros",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$goCommand = Get-Command go -ErrorAction SilentlyContinue
if (-not $goCommand) {
    throw "Go is required to package and verify the RouterOS image."
}

$arguments = @(
    "run", "./cmd/routeros-image",
    "--engine", $Engine,
    "--output-dir", $OutputDirectory
)
if (-not [string]::IsNullOrWhiteSpace($ImageTag)) {
    $arguments += @("--image", $ImageTag)
}
if (-not [string]::IsNullOrWhiteSpace($Builder)) {
    $arguments += @("--builder", $Builder)
}
if ($Force) {
    $arguments += "--force"
}

Push-Location -LiteralPath $projectRoot
try {
    & $goCommand.Source @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "RouterOS image packaging failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
