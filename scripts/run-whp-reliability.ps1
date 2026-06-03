param(
    [string]$KernelPath = "",

    [string]$InitrdPath = "",

    [int]$Cycles = 20,

    [string]$LogPath = "",

    [string]$ZigExe = "zig"
)

. "$PSScriptRoot\whp-common.ps1"

$KernelPath = Resolve-WhpGuestPath -Value $KernelPath -EnvName "M80_TEST_KERNEL" -Label "reliability kernel"
$InitrdPath = Resolve-WhpGuestPath -Value $InitrdPath -EnvName "M80_TEST_INITRD" -Label "reliability initrd"

if ($Cycles -lt 1) {
    $Cycles = 20
}

$env:M80_TEST_INTEGRATION = "whp-reliability"
$env:M80_TEST_KERNEL = $KernelPath
$env:M80_TEST_INITRD = $InitrdPath
$env:M80_TEST_WHP_RELIABILITY_CYCLES = "$Cycles"

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path -Path (Get-Location) -ChildPath "artifacts\whp-reliability.log"
}

Write-Host "WHP reliability: kernel=$KernelPath initrd=$InitrdPath cycles=$Cycles"
Write-Host "WHP reliability log: $LogPath"
Write-Host "WHP reliability zig: $ZigExe"

$zigExit = Invoke-WhpZigTest `
    -ZigExe $ZigExe `
    -TestFilter "integration: whp repeated start-stop reliability" `
    -LogPath $LogPath

Write-WhpLogClassification -LogPath $LogPath
if ($zigExit -ne 0) {
    exit $zigExit
}
