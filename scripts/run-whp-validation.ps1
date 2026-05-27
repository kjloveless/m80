param(
    [string]$KernelPath = "",

    [string]$InitrdPath = "",

    [int]$Cycles = 20,

    [string]$ArtifactsDir = "",

    [string]$ZigExe = "zig"
)

if ([string]::IsNullOrWhiteSpace($ArtifactsDir)) {
    $ArtifactsDir = Join-Path -Path (Get-Location) -ChildPath "artifacts"
}

if (-not (Test-Path -LiteralPath $ArtifactsDir)) {
    New-Item -ItemType Directory -Path $ArtifactsDir -Force | Out-Null
}

$smokeLog = Join-Path -Path $ArtifactsDir -ChildPath "whp-cpuid-io.log"
$reliabilityLog = Join-Path -Path $ArtifactsDir -ChildPath "whp-reliability.log"

Write-Host "WHP validation artifacts: $ArtifactsDir"
Write-Host "WHP validation: smoke first, reliability after smoke passes"

& "$PSScriptRoot\run-whp-integration.ps1" `
    -KernelPath $KernelPath `
    -InitrdPath $InitrdPath `
    -LogPath $smokeLog `
    -ZigExe $ZigExe
$smokeExit = $LASTEXITCODE
if ($smokeExit -ne 0) {
    Write-Error "WHP smoke failed; reliability was not run"
    exit $smokeExit
}

& "$PSScriptRoot\run-whp-reliability.ps1" `
    -KernelPath $KernelPath `
    -InitrdPath $InitrdPath `
    -Cycles $Cycles `
    -LogPath $reliabilityLog `
    -ZigExe $ZigExe
$reliabilityExit = $LASTEXITCODE
if ($reliabilityExit -ne 0) {
    exit $reliabilityExit
}

Write-Host "WHP validation passed: smoke and reliability completed"
