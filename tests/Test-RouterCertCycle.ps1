# Router write-path self-test: creates a throw-away 1-day certificate, signs it, exports it, verifies, then REMOVES it.
# .\tests\Test-RouterCertCycle.ps1 -Router <ip> -User <api-user> -Password ... -Ca <CA name> [-KeySize 2048|4096|secp384r1]
param([Parameter(Mandatory)][string]$Router, [Parameter(Mandatory)][string]$User, [string]$Password, [Parameter(Mandatory)][string]$Ca, [string]$KeySize = '2048')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($m in 'RouterOsApi', 'Checks', 'CertOps') { Import-Module (Join-Path $root "lib\$m.psm1") -Force -DisableNameChecking }
$name = 'OVPN-SELFTEST-DELETEME'
$c = Connect-RouterOs -Address $Router -User $User -Password $Password
try {
    $cert = New-OvpnClientCertificate -Connection $c -Name $name -CommonName 'SELFTEST' -Country 'UA' -KeySize $KeySize -Days 1 -Digest 'sha256' -CaName $Ca -SignTimeoutMin 5
    Write-OvpnLog -Level OK "Підписано: ca=$($cert['ca']) private-key=$($cert['private-key']) до $($cert['invalid-after'])"
    try {
        $exp = Export-RosCertificatePem -Connection $c -Name $name -Passphrase 'SelfTest-12345'
        $caPem = (Export-RosCertificatePem -Connection $c -Name $Ca).Cert
        Write-OvpnLog -Level OK "Експорт: cert $($exp.Cert.Length) b, key $($exp.Key.Length) b, CA $($caPem.Length) b"
        Test-OvpnCertificateLocal -CertPem $exp.Cert -KeyPem $exp.Key -CaPem $caPem -Passphrase 'SelfTest-12345' -ExpectedCn 'SELFTEST' |
            ForEach-Object { Write-OvpnLog -Level $(if ($_.Status -eq 'FAIL') { 'ERROR' } elseif ($_.Status -eq 'OK') { 'OK' } else { 'WARN' }) "$($_.Name): $($_.Detail)" }
    } catch { Write-OvpnLog -Level ERROR "Експорт/читання: $($_.Exception.Message)" }
}
finally {
    try {
        $left = Get-RosCert $c $name
        if ($left) { Remove-RosCert -Connection $c -Name $name; Write-OvpnLog -Level OK "Тестовий сертифікат $name видалено" }
        $tmp = Invoke-Ros $c '/file/print' | Where-Object { $_['name'] -like 'ovpnx-*' }
        foreach ($f in $tmp) { Remove-RosFile $c $f['name']; Write-OvpnLog "Видалено тимчасовий файл $($f['name'])" }
    } finally { Disconnect-RouterOs $c }
}
