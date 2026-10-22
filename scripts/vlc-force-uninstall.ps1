# Force-uninstall VLC and clear IME cached state.
# Run as admin on the Intune-enrolled host.

$ErrorActionPreference = 'SilentlyContinue'

# 1. Try the NSIS silent uninstaller
$paths = @(
    "$env:ProgramFiles\VideoLAN\VLC\uninstall.exe",
    "${env:ProgramFiles(x86)}\VideoLAN\VLC\uninstall.exe"
)
foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Host "[*] Running NSIS uninstaller: $p"
        Start-Process -FilePath $p -ArgumentList '/S' -Wait -NoNewWindow
        Start-Sleep -Seconds 3
    }
}

# 2. Remove VLC files if still present
foreach ($d in @("$env:ProgramFiles\VideoLAN", "${env:ProgramFiles(x86)}\VideoLAN")) {
    if (Test-Path $d) {
        Write-Host "[*] Removing directory: $d"
        Remove-Item -Path $d -Recurse -Force
    }
}

# 3. Remove uninstall registry keys
$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($root in $uninstallPaths) {
    Get-ChildItem $root | Where-Object {
        $_.GetValue('DisplayName') -like '*VLC*'
    } | ForEach-Object {
        Write-Host "[*] Removing uninstall key: $($_.PSPath)"
        Remove-Item $_.PSPath -Recurse -Force
    }
}

# 4. Clear IME cached app state
Write-Host "[*] Stopping IME service"
Stop-Service -Name IntuneManagementExtension -Force

$base = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension'
foreach ($sub in @('Win32Apps', 'OperationalState', 'Reporting', 'Win32Apps_GRS', 'SideCarPolicies\Scripts\Reports')) {
    $path = "$base\$sub"
    if (Test-Path $path) {
        Get-ChildItem $path | Remove-Item -Recurse -Force
        Write-Host "[*] Cleared $path"
    }
}

Write-Host "[*] Starting IME service"
Start-Service -Name IntuneManagementExtension

# 5. Verify
$vlcGone = -not (Test-Path "$env:ProgramFiles\VideoLAN") -and
           -not (Test-Path "${env:ProgramFiles(x86)}\VideoLAN")
if ($vlcGone) {
    Write-Host "[+] VLC removed from filesystem"
} else {
    Write-Host "[-] VLC files still present"
}

$regGone = $true
foreach ($root in $uninstallPaths) {
    if (Get-ChildItem $root | Where-Object { $_.GetValue('DisplayName') -like '*VLC*' }) {
        $regGone = $false
    }
}
if ($regGone) {
    Write-Host "[+] VLC removed from registry"
} else {
    Write-Host "[-] VLC registry keys still present"
}

Write-Host "[*] Done. Company Portal will re-evaluate on next check-in."
