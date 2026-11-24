# Certificate operations on RouterOS + local verification.

function Get-RosCert {
    param($Connection, [string]$Name)
    return Get-RosFirst $Connection '/certificate/print' -Query "?name=$Name"
}

# Creates (or reuses) a certificate and signs it. CaName empty → self-signed (new CA).
function New-RosSignedCertificate {
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$CommonName,
        [string]$Country = '',
        [string]$KeySize = '4096',
        [int]$Days = 365,
        [string]$Digest = 'sha256',
        [Parameter(Mandatory)][string]$KeyUsage,
        [string]$CaName = '',
        [int]$SignTimeoutMin = 90
    )
    $c = $Connection
    $existing = Get-RosCert $c $Name
    if ($existing -and ($existing['ca'] -or (Test-RosTrue $existing['authority']) -or $existing['issued'] -eq 'true')) {
        Write-OvpnLog -Level WARN "Сертифікат '$Name' вже існує і підписаний — використовую наявний"
        return $existing
    }
    if (-not $existing) {
        $a = [ordered]@{
            name = $Name; 'common-name' = $CommonName; 'key-size' = $KeySize; 'days-valid' = $Days
            'key-usage' = $KeyUsage; 'digest-algorithm' = $Digest
        }
        if ($Country) { $a['country'] = $Country }
        [void](Invoke-Ros $c '/certificate/add' -Arguments $a)
        $existing = Get-RosCert $c $Name
        if (-not $existing) { throw "Шаблон сертифіката '$Name' не створився" }
    } else {
        Write-OvpnLog -Level WARN "Шаблон '$Name' вже існує (не підписаний) — підписую його"
    }

    $id = $existing['.id']
    $by = if ($CaName) { "через $CaName" } else { 'самопідписом (CA)' }
    Write-OvpnLog "Підпис $Name ($KeySize) $by. Для великих ключів це може тривати кілька хвилин…"
    $started = Get-Date
    $sa = [ordered]@{}
    if ($CaName) { $sa['ca'] = $CaName }
    try {
        [void](Invoke-RosItemCommand -Connection $c -Command '/certificate/sign' -Id $id -Arguments $sa -TimeoutMs ($SignTimeoutMin * 60000))
    } catch {
        if ($_.Exception.Message -notmatch 'timed out|тайм') { throw }
        Write-OvpnLog -Level WARN "Команда sign не відповіла — перевіряю стан сертифіката"
    }
    $deadline = $started.AddMinutes($SignTimeoutMin)
    $lastLog = Get-Date
    while ((Get-Date) -lt $deadline) {
        $cert = Get-RosCert $c $Name
        $signed = $cert -and (Test-RosTrue $cert['private-key']) -and ($(if ($CaName) { [bool]$cert['ca'] } else { Test-RosTrue $cert['authority'] }))
        if ($signed) {
            Write-OvpnLog -Level OK ("Сертифікат $Name підписано за {0:mm\:ss}" -f ((Get-Date) - $started))
            return $cert
        }
        if (((Get-Date) - $lastLog).TotalSeconds -ge 30) {
            Write-OvpnLog ("…ще підписується ({0:mm\:ss})" -f ((Get-Date) - $started)); $lastLog = Get-Date
        }
        Start-Sleep -Seconds 3
    }
    throw "Сертифікат '$Name' не підписався за $SignTimeoutMin хв"
}

function New-OvpnClientCertificate {
    param(
        [Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$CommonName,
        [string]$Country = '', [string]$KeySize = '4096', [int]$Days = 365, [string]$Digest = 'sha256',
        [Parameter(Mandatory)][string]$CaName, [int]$SignTimeoutMin = 90
    )
    return New-RosSignedCertificate -Connection $Connection -Name $Name -CommonName $CommonName -Country $Country -KeySize $KeySize `
        -Days $Days -Digest $Digest -KeyUsage 'tls-client' -CaName $CaName -SignTimeoutMin $SignTimeoutMin
}

function Set-RosCertTrusted {
    param($Connection, [string]$Name)
    $cert = Get-RosCert $Connection $Name
    if (-not $cert) { throw "Сертифікат '$Name' не знайдено" }
    [void](Invoke-Ros $Connection '/certificate/set' -Arguments ([ordered]@{ '.id' = $cert['.id']; trusted = 'yes' }))
}

# Saves CA certificate + passphrase-encrypted private key to OutDir (disaster recovery).
function Export-OvpnCaBackup {
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$CaName, [Parameter(Mandatory)][string]$Passphrase, [Parameter(Mandatory)][string]$OutDir)
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $e = Export-RosCertificatePem -Connection $Connection -Name $CaName -Passphrase $Passphrase
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $crt = Join-Path $OutDir "$CaName-$stamp.crt"
    $key = Join-Path $OutDir "$CaName-$stamp.key"
    [System.IO.File]::WriteAllText($crt, $e.Cert)
    [System.IO.File]::WriteAllText($key, $e.Key)
    Write-OvpnLog -Level OK "Backup CA: $crt, $key (ключ зашифровано паскеєм)"
    return @($crt, $key)
}

# Exports certificate (+ encrypted key when Passphrase given) as PEM text, cleans up temp files.
function Export-RosCertificatePem {
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$Name, [string]$Passphrase)
    $c = $Connection
    $cert = Get-RosCert $c $Name
    if (-not $cert) { throw "Сертифікат '$Name' не знайдено" }
    $base = 'ovpnx-' + ([guid]::NewGuid().ToString('N').Substring(0, 10))
    $a = [ordered]@{ type = 'pem'; 'file-name' = $base }
    if ($Passphrase) { $a['export-passphrase'] = $Passphrase }
    $result = @{ Cert = $null; Key = $null }
    try {
        [void](Invoke-RosItemCommand -Connection $c -Command '/certificate/export-certificate' -Id $cert['.id'] -Arguments $a)
        $result.Cert = Read-RosFile $c "$base.crt"
        if ($Passphrase) { $result.Key = Read-RosFile $c "$base.key" }
    }
    finally {
        foreach ($f in @("$base.crt", "$base.key")) { try { Remove-RosFile $c $f } catch { Write-OvpnLog -Level WARN "Не вдалося видалити тимчасовий файл $f : $($_.Exception.Message)" } }
    }
    if ($result.Cert -notmatch 'BEGIN CERTIFICATE') { throw "Експорт '$Name': отримано не PEM-сертифікат" }
    if ($Passphrase -and $result.Key -notmatch 'BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY') { throw "Експорт '$Name': не отримано приватний ключ (перевірте політику 'sensitive')" }
    return $result
}

function Invoke-RosCertRevoke {
    param($Connection, [string]$Name)
    $cert = Get-RosCert $Connection $Name
    if (-not $cert) { throw "Сертифікат '$Name' не знайдено" }
    [void](Invoke-RosItemCommand -Connection $Connection -Command '/certificate/issued-revoke' -Id $cert['.id'])
}

function Remove-RosCert {
    param($Connection, [string]$Name)
    $cert = Get-RosCert $Connection $Name
    if (-not $cert) { throw "Сертифікат '$Name' не знайдено" }
    [void](Invoke-Ros $Connection '/certificate/remove' -Arguments ([ordered]@{ '.id' = $cert['.id'] }))
}

# ---------------------------------------------------------------- local PEM helpers
function Get-PemBlock {
    param([string]$Text, [string]$Label = 'CERTIFICATE')
    $m = [regex]::Match($Text, "-----BEGIN $Label-----(.+?)-----END $Label-----", 'Singleline')
    if (-not $m.Success) { return $null }
    return $m.Value
}

function Get-PemDer {
    param([string]$Pem)
    $b64 = ($Pem -replace '-----[^-]+-----', '' -replace '\s', '')
    return , [Convert]::FromBase64String($b64)
}

function ConvertTo-X509 {
    param([string]$Pem)
    $der = Get-PemDer (Get-PemBlock $Pem 'CERTIFICATE')
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $der)
}

function Get-X509Cn {
    param($Cert)
    return $Cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
}

# Verifies client cert/key/CA locally. Returns check objects.
function Test-OvpnCertificateLocal {
    param([string]$CertPem, [string]$KeyPem, [string]$CaPem, [string]$Passphrase, [string]$ExpectedCn)
    $out = New-Object System.Collections.Generic.List[object]
    $g = 'Локальна перевірка'
    try { $cert = ConvertTo-X509 $CertPem; $ca = ConvertTo-X509 $CaPem }
    catch { $out.Add((New-OvpnCheck $g 'Розбір PEM' 'FAIL' $_.Exception.Message '' -Critical)); return $out.ToArray() }

    $cn = Get-X509Cn $cert
    if ($ExpectedCn -and $cn -ne $ExpectedCn) { $out.Add((New-OvpnCheck $g 'CN' 'FAIL' "CN=$cn, очікувався $ExpectedCn" '' -Critical)) }
    else { $out.Add((New-OvpnCheck $g 'CN' 'OK' "CN=$cn, serial $($cert.SerialNumber)")) }

    $now = Get-Date
    if ($now -lt $cert.NotBefore.AddMinutes(-10) -or $now -gt $cert.NotAfter) { $out.Add((New-OvpnCheck $g 'Термін дії' 'FAIL' "$($cert.NotBefore) — $($cert.NotAfter)" 'Перевірте годинник роутера' -Critical)) }
    else { $out.Add((New-OvpnCheck $g 'Термін дії' 'OK' ("{0:yyyy-MM-dd} — {1:yyyy-MM-dd}" -f $cert.NotBefore, $cert.NotAfter))) }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
    [void]$chain.ChainPolicy.ExtraStore.Add($ca)
    $built = $chain.Build($cert)
    $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    $bad = @($chain.ChainStatus | Where-Object { $_.Status -ne 'UntrustedRoot' -and $_.Status -ne 'NoError' })
    if ($chain.ChainElements.Count -ge 2 -and $root.Thumbprint -eq $ca.Thumbprint -and $bad.Count -eq 0) {
        $out.Add((New-OvpnCheck $g 'Ланцюжок' 'OK' "Підписано $(Get-X509Cn $ca)"))
    } else {
        $out.Add((New-OvpnCheck $g 'Ланцюжок' 'FAIL' "Не підписано CA $(Get-X509Cn $ca): $(($bad | ForEach-Object { $_.StatusInformation.Trim() }) -join '; ')" '' -Critical))
    }

    $eku = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if ($eku -and ($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.2' })) { $out.Add((New-OvpnCheck $g 'Призначення' 'OK' 'TLS Web Client Authentication')) }
    else { $out.Add((New-OvpnCheck $g 'Призначення' 'WARN' 'Немає EKU clientAuth')) }

    if ($KeyPem) {
        if ($KeyPem -notmatch 'BEGIN ENCRYPTED PRIVATE KEY') { $out.Add((New-OvpnCheck $g 'Ключ' 'FAIL' 'Приватний ключ НЕ зашифрований паскеєм' '' -Critical)) }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            try {
                $pub = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
                if ($pub) {
                    $k = [System.Security.Cryptography.RSA]::Create()
                    $k.ImportFromEncryptedPem($KeyPem, $Passphrase)
                    $same = [Convert]::ToBase64String($k.ExportParameters($false).Modulus) -eq [Convert]::ToBase64String($pub.ExportParameters($false).Modulus)
                    $bits = $k.KeySize
                } else {
                    $pub = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert)
                    $k = [System.Security.Cryptography.ECDsa]::Create()
                    $k.ImportFromEncryptedPem($KeyPem, $Passphrase)
                    $same = [Convert]::ToBase64String($k.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToBase64String($pub.ExportSubjectPublicKeyInfo())
                    $bits = $k.KeySize
                }
                if ($same) { $out.Add((New-OvpnCheck $g 'Ключ ↔ сертифікат' 'OK' "Паскей підходить, ключ $bits біт відповідає сертифікату")) }
                else { $out.Add((New-OvpnCheck $g 'Ключ ↔ сертифікат' 'FAIL' 'Ключ не відповідає сертифікату' '' -Critical)) }
            } catch {
                $out.Add((New-OvpnCheck $g 'Ключ ↔ сертифікат' 'FAIL' "Не вдалося розшифрувати ключ паскеєм: $($_.Exception.InnerException.Message)$($_.Exception.Message)" '' -Critical))
            }
        } else {
            $out.Add((New-OvpnCheck $g 'Ключ ↔ сертифікат' 'WARN' 'Перевірка паскею доступна лише в PowerShell 7 (встановіть pwsh)'))
        }
    }
    return $out.ToArray()
}

Export-ModuleMember -Function Get-RosCert, New-RosSignedCertificate, New-OvpnClientCertificate, Set-RosCertTrusted, Export-OvpnCaBackup, Export-RosCertificatePem, Invoke-RosCertRevoke, Remove-RosCert,
    Get-PemBlock, Get-PemDer, ConvertTo-X509, Get-X509Cn, Test-OvpnCertificateLocal
