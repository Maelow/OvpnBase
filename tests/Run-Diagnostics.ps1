# Console diagnostics (read-only): .\tests\Run-Diagnostics.ps1 -Router <ip> -User <api-user> [-VpnHost vpn.example.com]
param(
    [Parameter(Mandatory)][string]$Router,
    [int]$ApiPort = 8728,
    [Parameter(Mandatory)][string]$User,
    [string]$Password,
    [string]$VpnHost,
    [int]$ProbePort = 0
)
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'lib\RouterOsApi.psm1') -Force
Import-Module (Join-Path $root 'lib\Checks.psm1') -Force

if (-not $Password) {
    $sec = Read-Host -AsSecureString "Пароль API для $User@$Router"
    $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
$c = Connect-RouterOs -Address $Router -Port $ApiPort -User $User -Password $Password
try {
    $st = Get-RouterState -Connection $c
    $checks = Test-RouterState -State $st -VpnHost $VpnHost
    $checks | Format-Table Icon, Group, Name, Detail -AutoSize -Wrap
    $checks | Where-Object { $_.Fix } | Format-Table Status, Name, Fix -AutoSize -Wrap
    if ($ProbePort) {
        "--- Перевірка порту $ProbePort"
        $free = Test-OvpnPortFree $st $ProbePort
        if ($free) { $free } else { 'Порт вільний' }
        (Test-ZeroTrustPort -State $st -Port $ProbePort).Checks | Format-Table Icon, Name, Detail -AutoSize -Wrap
    }
    "Запропонований порт: $(Get-OvpnSuggestedPort $st)"
} finally { Disconnect-RouterOs $c }
