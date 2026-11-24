# Offline self-test (PowerShell 7): local cert check, profiles, archives. Optional read-only plan against a router.
# .\tests\Test-Offline.ps1 [-Router <ip> -User <api-user> -Password ...]
param([string]$Router, [string]$User, [string]$Password, [string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($m in 'RouterOsApi', 'Checks', 'CertOps', 'Profile', 'Archive', 'Workflow', 'Setup') { Import-Module (Join-Path $root "lib\$m.psm1") -Force -DisableNameChecking }
if (-not $OutDir) { $OutDir = Join-Path ([IO.Path]::GetTempPath()) ("ovpn-selftest-" + [guid]::NewGuid().ToString('N').Substring(0, 6)) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$fail = 0
function Assert($cond, $msg) { if ($cond) { Write-Host "  PASS $msg" -ForegroundColor Green } else { Write-Host "  FAIL $msg" -ForegroundColor Red; $script:fail++ } }

Write-Host '== Генерація тестового CA та клієнтського сертифіката'
$caKey = [System.Security.Cryptography.RSA]::Create(2048)
$caReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('C=UA, CN=TEST-CA', $caKey, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$caReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
$caReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('KeyCertSign, CrlSign', $true))
$ca = $caReq.CreateSelfSigned((Get-Date).AddDays(-1), (Get-Date).AddYears(5))
$clKey = [System.Security.Cryptography.RSA]::Create(2048)
$clReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('C=UA, CN=CL-TEST', $clKey, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$oids = [System.Security.Cryptography.OidCollection]::new(); [void]$oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2'))
$clReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))
$serial = [byte[]](1..8)
$cl = $clReq.Create($ca, (Get-Date).AddMinutes(-5), (Get-Date).AddDays(360), $serial)
$pem = { param($c) "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n" }
$caPem = & $pem $ca; $clPem = & $pem $cl
$pp = [System.Security.Cryptography.PbeParameters]::new('Aes256Cbc', 'SHA256', 10000)
$keyPem = $clKey.ExportEncryptedPkcs8PrivateKeyPem('Passkey-123', $pp)

Write-Host '== Test-OvpnCertificateLocal'
$r = Test-OvpnCertificateLocal -CertPem $clPem -KeyPem $keyPem -CaPem $caPem -Passphrase 'Passkey-123' -ExpectedCn 'CL-TEST'
$r | ForEach-Object { "    $($_.Icon) $($_.Name): $($_.Detail)" }
Assert (-not ($r | Where-Object Status -eq 'FAIL')) 'правильний паскей → без FAIL'
$r2 = Test-OvpnCertificateLocal -CertPem $clPem -KeyPem $keyPem -CaPem $caPem -Passphrase 'wrong-pass' -ExpectedCn 'CL-TEST'
Assert ($r2 | Where-Object { $_.Status -eq 'FAIL' -and $_.Name -like 'Ключ*' }) 'невірний паскей → FAIL'
$otherCa = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=OTHER', [System.Security.Cryptography.RSA]::Create(2048), 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1).CreateSelfSigned((Get-Date).AddDays(-1), (Get-Date).AddYears(1))
$r3 = Test-OvpnCertificateLocal -CertPem $clPem -KeyPem $keyPem -CaPem (& $pem $otherCa) -Passphrase 'Passkey-123'
Assert ($r3 | Where-Object { $_.Status -eq 'FAIL' -and $_.Name -eq 'Ланцюжок' }) 'чужий CA → FAIL ланцюжка'

Write-Host '== Профілі'
$routes = @('10.10.1.0/24', '10.10.2.0 255.255.255.0', '10.10.3.0/24')
$prof = Join-Path $OutDir 'profiles'; New-Item -ItemType Directory -Force -Path $prof | Out-Null
foreach ($pl in 'Windows', 'macOS') {
    $t = New-OvpnProfileText -Platform $pl -Hosts @('vpn.example.com', 'vpn2.example.com') -Port 41663 -Protocol tcp -CaPem $caPem -CertPem $clPem -KeyPem $keyPem `
        -FriendlyName 'VPN Connection TEST' -Routes $routes -ServerCn 'OVPN-SRV-TEST' -Modern $true
    [IO.File]::WriteAllText((Join-Path $prof "VPN-TEST-$pl.ovpn"), $t)
    Assert ($t -match 'remote vpn\.example\.com 41663' -and $t -match 'remote vpn2\.example\.com 41663') "$pl : remote хости з портом"
    Assert ($t -match 'route 10\.10\.1\.0 255\.255\.255\.0' -and $t -match 'route 10\.10\.2\.0 255\.255\.255\.0') "$pl : маршрути"
    Assert ($t -match 'remote-cert-tls server' -and $t -match 'verify-x509-name OVPN-SRV-TEST name' -and $t -notmatch 'ns-cert-type') "$pl : сучасні опції"
    Assert ($t -match 'BEGIN ENCRYPTED PRIVATE KEY') "$pl : ключ зашифрований"
    if ($pl -eq 'Windows') { Assert ($t -match 'route-method exe' -and $t -match "`r`n") 'Windows: route-method + CRLF' }
    else { Assert ($t -notmatch 'route-method|ip-win32' -and $t -notmatch "`r`n") 'macOS: без Windows-опцій, LF' }
}
$prev = Get-ChildItem -Path (Join-Path $root 'sample') -Filter *.ovpn -ErrorAction SilentlyContinue | Select-Object -First 1
if ($prev) { $info = Read-OvpnProfileInfo $prev.FullName; Assert ($info.Hosts.Count -ge 1 -and $info.Port -gt 0) "розбір $($prev.Name): хост, порт $($info.Port), маршрутів $($info.Routes.Count)" }
$tmpProf = Join-Path $OutDir 'parse-test.ovpn'
[IO.File]::WriteAllText($tmpProf, "client`nremote vpn.example.com`nport 1194`nroute 10.1.0.0 255.255.0.0`nsetenv FRIENDLY_NAME `"VPN 2026`"`n")
$pi = Read-OvpnProfileInfo $tmpProf
Assert ($pi.Hosts[0] -eq 'vpn.example.com' -and $pi.Port -eq 1194 -and $pi.Routes[0] -eq '10.1.0.0/16' -and $pi.FriendlyName -eq 'VPN 2026') 'Read-OvpnProfileInfo'

Write-Host '== Архіви'
$sz = Get-SevenZip -ToolsDir (Join-Path $root 'tools\7z')
foreach ($pl in 'Windows', 'macOS') { [IO.File]::WriteAllText((Join-Path $prof "README-$pl.txt"), (New-OvpnReadme -Platform $pl -ProfileName "VPN-TEST-$pl.ovpn" -Year 2099 -ValidTo '2099-12-31')) }
$pw = 'Arch!ve#Pass_2099'
$a = New-OvpnArchive -SevenZip $sz -Kind Sfx -OutFile (Join-Path $OutDir 'VPN-TEST.exe') -Files @((Join-Path $prof 'VPN-TEST-Windows.ovpn'), (Join-Path $prof 'README-Windows.txt')) -WorkDir $prof -Password $pw
Assert ($a.Length -gt 100KB -and ([IO.File]::ReadAllBytes($a.FullName)[0..1] -join ',') -eq '77,90') "SFX exe ($([int]($a.Length/1KB)) KB, MZ-заголовок)"
$b = New-OvpnArchive -SevenZip $sz -Kind ZipAes -OutFile (Join-Path $OutDir 'VPN-TEST-macOS-AES.zip') -Files @((Join-Path $prof 'VPN-TEST-macOS.ovpn'), (Join-Path $prof 'README-macOS.txt')) -WorkDir $prof -Password $pw
$c = New-OvpnArchive -SevenZip $sz -Kind ZipCrypto -OutFile (Join-Path $OutDir 'VPN-TEST-macOS.zip') -Files @((Join-Path $prof 'VPN-TEST-macOS.ovpn'), (Join-Path $prof 'README-macOS.txt')) -WorkDir $prof -Password $pw
$lt = Invoke-SevenZip -Exe $sz.Exe -Arguments @('l', '-slt', "-p$pw", '--', $b.FullName) -WorkDir $OutDir
Assert ($lt -match 'Method = AES-256') 'zip AES-256'
$lt2 = Invoke-SevenZip -Exe $sz.Exe -Arguments @('l', '-slt', "-p$pw", '--', $c.FullName) -WorkDir $OutDir
Assert ($lt2 -match 'Method = ZipCrypto') 'zip ZipCrypto'
$hdr = $null; try { $hdr = Invoke-SevenZip -Exe $sz.Exe -Arguments @('l', '-pX', '--', $a.FullName) -WorkDir $OutDir } catch { }
Assert (-not ($hdr -match 'VPN-TEST-Windows')) 'SFX: імена файлів приховані без пароля'
$exdir = Join-Path $OutDir 'extract'
[void](Invoke-SevenZip -Exe $sz.Exe -Arguments @('x', "-p$pw", "-o$exdir", '-y', '--', $a.FullName) -WorkDir $OutDir)
Assert ((Get-FileHash (Join-Path $exdir 'VPN-TEST-Windows.ovpn')).Hash -eq (Get-FileHash (Join-Path $prof 'VPN-TEST-Windows.ovpn')).Hash) 'SFX розпаковується з паролем, вміст ідентичний'

Write-Host '== Допоміжні'
Assert ((Get-NewDstPort '52431,8291,8728,8729' 52431 41663) -eq '52431,41663,8291,8728,8729') 'Get-NewDstPort вставляє після старого порту'
Assert ((Get-NewDstPort '52431,41663,8291' 52431 41663) -eq '52431,41663,8291') 'Get-NewDstPort ідемпотентний'
Assert (Test-PortInSpec '8000-8100,52431' 8050) 'Test-PortInSpec діапазон'
Assert ((ConvertTo-WinArg 'a b"c\') -eq '"a b\"c\\"') 'ConvertTo-WinArg екранування'

if ($Router) {
    Write-Host "== Read-only план для $Router"
    $conn = Connect-RouterOs -Address $Router -User $User -Password $Password
    try { $st = Get-RouterState -Connection $conn } finally { Disconnect-RouterOs $conn }
    $port = Get-OvpnSuggestedPort $st
    $P = @{ Year = (Get-Date).Year + 1; Days = 400; SourceServer = $st.Servers[0]['name']; NewServerName = "ovpn-server-$((Get-Date).Year + 1)"; Port = $port
        VpnHost = 'vpn.example.com'; VpnHost2 = ''; Routes = $routes; CertName = "OVPN-CL-$((Get-Date).Year + 1)"; CertCn = "CL-$((Get-Date).Year + 1)"; Country = 'UA'
        KeySize = '16384'; Digest = 'sha512'; KeyPass = 'Passkey-123'; ArchivePass = $pw; FriendlyName = 'VPN'; PortalUrl = ''; Modern = $true; DeleteOpen = $false
        DoBackup = $true; Schedule = $true; CutDate = "$((Get-Date).Year + 1)-01-15"; CutTime = '03:00'; OutDir = $OutDir; ToolsDir = (Join-Path $root 'tools\7z'); AllowList = 'MGMT_Allow' }
    $errs = Test-OvpnParams -State $st -P $P
    $errs | ForEach-Object { "    ! $_" }
    Assert ($errs.Count -eq 0) 'Test-OvpnParams без помилок'
    (Get-OvpnBuildPlan -State $st -P $P) | ForEach-Object { "    $_" }
    Write-Host "== Read-only план: локальні користувачі"
    $P2 = $P.Clone(); $P2.AuthMode = 'local'; $P2.KeySize = '4096'; $P2.UserCertTpl = 'OVPN-CL-{user}-{year}'; $P2.UserProfile = 'VPN_POOL'
    $known = @($st.Secrets | Where-Object { $_['service'] -in @('ovpn', 'any') } | ForEach-Object { $_['name'] })
    if ($known.Count -eq 0) { Write-Host '  SKIP local: на роутері немає /ppp secret'; $known = @('__none__') }
    $P2.Users = @(@{ Name = $known[0]; Password = ''; IsNew = $false }, @{ Name = 'test.user1'; Password = ''; IsNew = $true }, @{ Name = 'test.user2'; Password = 'Str0ng-Pass!'; IsNew = $true })
    $e2 = Test-OvpnParams -State $st -P $P2; $e2 | ForEach-Object { "    ! $_" }
    Assert ($e2.Count -eq 0) 'local: Test-OvpnParams без помилок'
    (Get-OvpnBuildPlan -State $st -P $P2) | Where-Object { $_ -match 'режим|ppp secret|наявні|users|OVPN-CL-' } | ForEach-Object { "    $_" }
    $P3 = $P2.Clone(); $P3.Users = @(@{ Name = $known[0]; Password = ''; IsNew = $true }, @{ Name = 'bad name'; Password = ''; IsNew = $true }, @{ Name = 'ghost'; Password = ''; IsNew = $false })
    $e3 = Test-OvpnParams -State $st -P $P3
    Assert (($e3 -match 'вже існує').Count -and ($e3 -match 'Некоректний логін').Count -and ($e3 -match 'немає на роутері').Count) 'local: ловить дубль, некоректний логін, неіснуючого'
    $ids = @(Get-OvpnIdentities -P $P2)
    Assert ($ids.Count -eq 3 -and $ids[1].CertName -eq "OVPN-CL-test.user1-$($P2.Year)" -and $ids[1].CertCn -eq 'test.user1') 'local: ідентичності CN=логін'

    Write-Host "== Read-only план: первинне налаштування"
    $S = Get-OvpnSetupDefaults $st
    $S = @{} + $S; $S.CaBackupPass = ''; $S.OutDir = $OutDir
    $se = Test-OvpnSetupParams -State $st -S $S; $se | ForEach-Object { "    ! $_" }
    Assert ($se.Count -eq 0) 'setup на налаштованому роутері: без помилок'
    $sp = Get-OvpnSetupPlan -State $st -S $S
    Assert (-not ($sp -match 'add name=')) 'setup на налаштованому роутері: нічого не створюється'
    # simulated fresh router: no OVPN objects
    $fresh = @{} + $st
    $fresh.Servers = @(); $fresh.Certificates = @(); $fresh.Pools = @(); $fresh.Profiles = @($st.Profiles | Where-Object { $_['name'] -eq 'default' })
    $fresh.Radius = @(); $fresh.Aaa = [ordered]@{ 'use-radius' = 'false' }
    $fresh.Filter = @($st.Filter | Where-Object { $_['.id'] -ne '*64' })
    $F = Get-OvpnSetupDefaults $fresh
    $F = @{} + $F; $F.CaBackupPass = 'Backup-Pass-1'; $F.OutDir = $OutDir; $F.RadiusEnable = $true; $F.RadiusAddress = '10.0.0.2'; $F.RadiusSecret = 'secret-12345'
    $fe = Test-OvpnSetupParams -State $fresh -S $F; $fe | ForEach-Object { "    ! $_" }
    Assert ($fe.Count -eq 0) 'setup на «чистому» роутері: без помилок'
    (Get-OvpnSetupPlan -State $fresh -S $F) | ForEach-Object { "    $_" }
    "    --- cutover script:"
    (Get-CutoverScript -RuleId '*64' -OldPort 52431 -OldServer 'ovpn-server1' -SchedName 'ovpn-cutover-2027') -split "`n" | ForEach-Object { "    $_" }
}

Write-Host ''
if ($fail) { Write-Host "ПРОВАЛЕНО: $fail" -ForegroundColor Red; exit 1 } else { Write-Host "Усі тести пройдено. Тека: $OutDir" -ForegroundColor Green }
