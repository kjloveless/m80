function Resolve-WhpGuestPath {
    param(
        [string]$Value,
        [string]$EnvName,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Value = [Environment]::GetEnvironmentVariable($EnvName)
    }

    if ([string]::IsNullOrWhiteSpace($Value) -or -not (Test-Path -LiteralPath $Value)) {
        Write-Error "missing WHP $Label`: $Value"
        exit 2
    }

    return $Value
}

function Ensure-WhpLogDirectory {
    param([string]$LogPath)

    $logDir = Split-Path -Parent $LogPath
    if (-not [string]::IsNullOrWhiteSpace($logDir) -and -not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
}

function Invoke-WhpZigTest {
    param(
        [string]$ZigExe,
        [string]$TestFilter,
        [string]$LogPath
    )

    Ensure-WhpLogDirectory -LogPath $LogPath
    try {
        & $ZigExe build test -- --test-filter $TestFilter 2>&1 |
            Tee-Object -FilePath $LogPath
        if ($null -eq $LASTEXITCODE) {
            return 0
        }
        return $LASTEXITCODE
    } catch {
        $_ | Tee-Object -FilePath $LogPath -Append
        return 1
    }
}

function Write-WhpLogClassification {
    param(
        [string]$LogPath
    )

    if ([string]::IsNullOrWhiteSpace($LogPath) -or -not (Test-Path -LiteralPath $LogPath)) {
        return
    }

    $patterns = @(
        @{ Name = "interrupt_window_exit"; Pattern = "interrupt window exit" },
        @{ Name = "apic_eoi_exit"; Pattern = "apic eoi exit" },
        @{ Name = "msr_access_exit"; Pattern = "msr access exit" },
        @{ Name = "exception_exit"; Pattern = "exception exit" },
        @{ Name = "memory_access_exit"; Pattern = "memory access exit" },
        @{ Name = "mmio_emulation_failed"; Pattern = "mmio emulation failed" },
        @{ Name = "virtio_irq_injection_failed"; Pattern = "failed to inject virtio irq" },
        @{ Name = "vsock_packet_delivery_failed"; Pattern = "virtio-vsock packet delivery failed" },
        @{ Name = "vsock_tx_notify_failed"; Pattern = "virtio-vsock tx notify failed" }
    )

    Add-Content -LiteralPath $LogPath -Value "" -Encoding utf8
    Add-Content -LiteralPath $LogPath -Value "=== WHP exit classification ===" -Encoding utf8
    foreach ($item in $patterns) {
        $matches = Select-String -LiteralPath $LogPath -Pattern $item.Pattern -SimpleMatch -ErrorAction SilentlyContinue
        $count = @($matches).Count
        Add-Content -LiteralPath $LogPath -Value ("{0}={1}" -f $item.Name, $count) -Encoding utf8
    }

    $unknowns = Select-String -LiteralPath $LogPath -Pattern "unknown exit reason=0x([0-9a-fA-F]+)" -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Matches } |
        ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } |
        Group-Object |
        Sort-Object Name

    if (@($unknowns).Count -eq 0) {
        Add-Content -LiteralPath $LogPath -Value "unknown_exit_reasons=none" -Encoding utf8
    } else {
        foreach ($group in $unknowns) {
            Add-Content -LiteralPath $LogPath -Value ("unknown_exit_reason_0x{0}={1}" -f $group.Name, $group.Count) -Encoding utf8
        }
    }
}
