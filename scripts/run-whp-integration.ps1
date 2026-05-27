param(
    [string]$KernelPath = "",

    [string]$InitrdPath = "",

    [string]$LogPath = "",

    [string]$ZigExe = "zig"
)

. "$PSScriptRoot\whp-common.ps1"

$KernelPath = Resolve-WhpGuestPath -Value $KernelPath -EnvName "M80_TEST_KERNEL" -Label "integration kernel"
$InitrdPath = Resolve-WhpGuestPath -Value $InitrdPath -EnvName "M80_TEST_INITRD" -Label "integration initrd"

$env:M80_TEST_INTEGRATION = "whp"
$env:M80_TEST_KERNEL = $KernelPath
$env:M80_TEST_INITRD = $InitrdPath

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path -Path (Get-Location) -ChildPath "artifacts\whp-cpuid-io.log"
}

Write-Host "WHP integration: kernel=$KernelPath initrd=$InitrdPath"
Write-Host "WHP integration log: $LogPath"
Write-Host "WHP integration zig: $ZigExe"

$zigExit = Invoke-WhpZigTest `
    -ZigExe $ZigExe `
    -TestFilter "integration: cpuid/io port exits keep vcpu running" `
    -LogPath $LogPath

Write-WhpLogClassification -LogPath $LogPath
if ($zigExit -ne 0) {
    exit $zigExit
}
