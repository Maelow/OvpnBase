# Router write-path self-test. Everything it creates is temporary and removed in `finally`:
#   A. certificate cycle (RSA 2048 + EC P-384): create, sign, export, local verify, remove
#   B. /export backup + /file/read
#   C. cutover script logic on a DISABLED dummy firewall rule (no effect on traffic)
#   D. Invoke-OvpnSetup on an already configured router (all steps must skip) + CA backup
#   E. Invoke-OvpnBuild without port change: RADIUS mode and local-users mode (temporary /ppp secret)
# .\tests\Test-RouterWrite.ps1 -Router <ip> -User <api-user> -Password ...
param([Parameter(Mandatory)][string]$Router, [Parameter(Mandatory)][string]$User, [Parameter(Mandatory)][string]$Password, [switch]$SkipEc)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($m in 'RouterOsApi', 'Checks', 'CertOps', 'Profile', 'Archive', 'Workflow', 'Setup') { Import-Module (Join-Path $root "lib\$m.psm1") -Force -DisableNameChecking }

$tag = 'OVPNBASE-SELFTEST'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ovpnbase-write-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$script:fail = 0
function Assert($cond, $msg) { if ($cond) { Write-Host "  PASS $msg" -ForegroundColor Green } else { Write-Host "  FAIL $msg" -ForegroundColor Red; $script:fail++ } }
function Section($t) { Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }

$c = Connect-RouterOs -Address $Router -User $User -Password $Password
$st = Get-RouterState -Connection $c
$src = $st.Servers | Where-Object { -not (Test-RosTrue $_['disabled']) } | Select-Object -First 1
$caName = (Get-StateCert $st $src['certificate'])['ca']
$created = @{ Certs = @(); Secrets = @(); Rules = @(); Scripts = @(); Servers = @() }
Write-Host "Роутер $($st.Identity), сервер $($src['name']):$($src['port']), CA $caName"

try {
    # ------------------------------------------------------------------ A
    $kinds = @(@{ Key = '2048'; Label = 'RSA 2048' })
    if (-not $SkipEc) { $kinds += @{ Key = 'secp384r1'; Label = 'EC P-384' } }
    foreach ($k in $kinds) {
        Section "A. Сертифікат $($k.Label)"
        $name = "$tag-$($k.Key)"
        $created.Certs += $name
        $t0 = Get-Date
        $cert = New-OvpnClientCertificate -Connection $c -Name $name -CommonName "selftest-$($k.Key)" -Country 'UA' -KeySize $k.Key -Days 1 -Digest 'sha256' -CaName $caName -SignTimeoutMin 10
        Assert ($cert['ca'] -eq $caName -and (Test-RosTrue $cert['private-key'])) ("підписано CA за {0:N1} с" -f ((Get-Date) - $t0).TotalSeconds)
        $e = Export-RosCertificatePem -Connection $c -Name $name -Passphrase 'Selftest-Pass-1'
        $caPem = (Export-RosCertificatePem -Connection $c -Name $caName).Cert
        Assert ($e.Cert -match 'BEGIN CERTIFICATE' -and $e.Key -match 'BEGIN ENCRYPTED PRIVATE KEY') "експорт: cert $($e.Cert.Length) b, ключ зашифрований $($e.Key.Length) b"
        $v = Test-OvpnCertificateLocal -CertPem $e.Cert -KeyPem $e.Key -CaPem $caPem -Passphrase 'Selftest-Pass-1' -ExpectedCn "selftest-$($k.Key)"
        $v | ForEach-Object { "    $($_.Icon) $($_.Name): $($_.Detail)" }
        Assert (-not ($v | Where-Object Status -eq 'FAIL')) 'локальна перевірка без FAIL'
        $left = @(Invoke-Ros $c '/file/print' | Where-Object { $_['name'] -like 'ovpnx-*' })
        Assert ($left.Count -eq 0) 'тимчасові файли експорту видалено'
    }

    # ------------------------------------------------------------------ B
    Section 'B. Backup конфігу (/export + /file/read)'
    $fn = "$tag-export"
    [void](Invoke-Ros $c '/export' -Arguments ([ordered]@{ file = $fn }) -TimeoutMs 180000)
    try {
        $txt = Read-RosFile $c "$fn.rsc"
        Assert ($txt.Length -gt 1000 -and $txt -match '/interface ovpn-server server') "export прочитано: $($txt.Length) байт, містить ovpn-server"
        Assert ($txt -notmatch 'secret=\S{6,}' -or $txt -match 'hide-sensitive|#.*sensitive') 'секрети в export приховані (без show-sensitive)'
    } finally { Remove-RosFile $c "$fn.rsc" }
    Assert (-not (Get-RosFile $c "$fn.rsc")) 'тимчасовий .rsc видалено'

    # ------------------------------------------------------------------ C
    Section 'C. Скрипт переходу (на вимкненому тестовому правилі)'
    $ruleId = Invoke-RosRet $c '/ip/firewall/filter/add' -Arguments ([ordered]@{
            chain = 'input'; action = 'accept'; protocol = 'tcp'; 'dst-port' = '11111,22222,33333'; disabled = 'yes'; comment = "$tag dummy (safe to delete)"
        })
    $created.Rules += $ruleId
    $sched = "$tag-cutover"
    $scr = Get-CutoverScript -RuleId $ruleId -OldPort 22222 -OldServer "$tag-no-such-server" -SchedName $sched
    $sid = Invoke-RosRet $c '/system/script/add' -Arguments ([ordered]@{ name = "$tag-script"; source = $scr; policy = 'read,write,test' })
    $created.Scripts += $sid
    [void](Invoke-RosItemCommand -Connection $c -Command '/system/script/run' -Id $sid)
    Start-Sleep -Seconds 2
    $r = Get-RosFirst $c '/ip/firewall/filter/print' -Query "?.id=$ruleId"
    Assert ($r['dst-port'] -eq '11111,33333') "dst-port після скрипта: '$($r['dst-port'])' (очікувалось 11111,33333)"
    Assert (Test-RosTrue $r['disabled']) 'тестове правило лишилось вимкненим'

    Section 'C2. Перехід: відкликання сертифіката + видалення сервера (тимчасові обʼєкти)'
    $oldCert = "$tag-OLDCERT"; $created.Certs += $oldCert
    [void](New-OvpnClientCertificate -Connection $c -Name $oldCert -CommonName 'selftest-old' -KeySize '2048' -Days 1 -Digest 'sha256' -CaName $caName -SignTimeoutMin 5)
    $dSrv = "$tag-oldsrv"; $created.Servers += $dSrv
    $used = Get-UsedPorts $st; $dp = 61000; while ($used.ContainsKey($dp)) { $dp++ }
    [void](Invoke-Ros $c '/interface/ovpn-server/server/add' -Arguments ([ordered]@{ 'copy-from' = $src['.id']; name = $dSrv; port = $dp; disabled = 'yes'; 'mac-address' = '02:00:5E:00:53:01'; comment = "$tag (safe to delete)" }))
    Assert ((Get-RosFirst $c '/interface/ovpn-server/server/print' -Query "?name=$dSrv") -ne $null) "тимчасовий вимкнений сервер ${dSrv}:${dp} створено"
    $scr2 = Get-CutoverScript -OldServer $dSrv -SchedName "$tag-cut2" -RevokeCerts @($oldCert) -RemoveServer
    $sid2 = Invoke-RosRet $c '/system/script/add' -Arguments ([ordered]@{ name = "$tag-script2"; source = $scr2; policy = 'read,write,test' })
    $created.Scripts += $sid2
    [void](Invoke-RosItemCommand -Connection $c -Command '/system/script/run' -Id $sid2)
    Start-Sleep -Seconds 2
    Assert ((Get-RosFirst $c '/interface/ovpn-server/server/print' -Query "?name=$dSrv") -eq $null) 'скрипт видалив старий сервер'
    $oc = Get-RosCert $c $oldCert
    Assert (Test-RosTrue $oc['revoked']) "скрипт відкликав сертифікат (revoked=$($oc['revoked']))"

    # ------------------------------------------------------------------ D
    Section 'D. Первинне налаштування на налаштованому роутері + backup CA'
    $S = @{} + (Get-OvpnSetupDefaults $st)
    $S.CaBackupPass = 'Selftest-Backup-1'; $S.OutDir = (Join-Path $tmp 'ca'); $S.RadiusEnable = $false
    $before = (Invoke-Ros $c '/interface/ovpn-server/server/print').Count
    $sr = Invoke-OvpnSetup -Connection $c -S $S
    $after = (Invoke-Ros $c '/interface/ovpn-server/server/print').Count
    Assert ($before -eq $after) "серверів не додано ($after)"
    Assert ($sr.Files.Count -eq 2 -and (Get-Content $sr.Files[1] -Raw) -match 'BEGIN ENCRYPTED PRIVATE KEY') 'backup CA: .crt + зашифрований .key'

    # ------------------------------------------------------------------ E
    $year = (Get-Date).Year + 1
    $base = @{
        Year = $year; Days = 30; SourceServer = $src['name']; NewServerName = "$tag-srv"; Port = [int]$src['port']
        VpnHost = 'vpn.example.com'; VpnHost2 = ''; Routes = @('10.99.0.0/24'); Country = 'UA'; KeySize = '2048'; Digest = 'sha256'
        KeyPass = 'Selftest-Key-123'; ArchivePass = 'Selftest-Arc-456'; FriendlyName = 'Selftest'; PortalUrl = ''; IncludeReadme = $true
        Modern = $true; DeleteOpen = $false; DoBackup = $true; Schedule = $false; CutDate = ''; CutTime = ''
        ToolsDir = (Join-Path $root 'tools\7z'); AllowList = $st.AllowList; UserProfile = $src['default-profile']; UserCertTpl = "$tag-{user}-{year}"; SaveCredentials = $true
    }
    Section 'E1. Збірка: режим RADIUS, без зміни порту'
    $P = @{} + $base; $P.AuthMode = 'radius'; $P.CertName = "$tag-RADIUS"; $P.CertCn = 'selftest-radius'; $P.Users = @(); $P.OutDir = (Join-Path $tmp 'radius')
    $created.Certs += $P.CertName
    $res = Invoke-OvpnBuild -Connection $c -P $P
    $names = $res.Files | ForEach-Object { Split-Path -Leaf $_ }
    Assert ($names -contains "VPN-$year.exe" -and $names -contains "VPN-$year-macOS-AES.zip" -and $names -contains "VPN-$year-macOS.zip") '3 архіви'
    Assert (@($names | Where-Object { $_ -like 'backup-*.rsc' }).Count -eq 1) 'backup конфігу збережено'
    $sz = Get-SevenZip -ToolsDir $P.ToolsDir
    $x = Join-Path $tmp 'x-radius'
    [void](Invoke-SevenZip -Exe $sz.Exe -Arguments @('x', "-p$($P.ArchivePass)", "-o$x", '-y', '--', (Join-Path $P.OutDir "VPN-$year.exe")) -WorkDir $tmp)
    $prof = Get-Content (Join-Path $x "VPN-$year-Windows.ovpn") -Raw
    Assert ($prof -match "remote vpn\.example\.com $($src['port'])" -and $prof -match 'verify-x509-name' -and $prof -match 'BEGIN ENCRYPTED PRIVATE KEY') 'SFX: профіль з правильним remote/портом і зашифрованим ключем'
    Assert (Test-Path (Join-Path $x 'README-Windows.txt')) 'SFX: README (IncludeReadme=true)'
    Assert ((Get-RosFirst $c '/interface/ovpn-server/server/print' -Query "?name=$tag-srv") -eq $null) 'паралельний сервер НЕ створено (порт не змінювався)'

    Section 'E2. Збірка: локальні користувачі (тимчасовий /ppp secret)'
    $P = @{} + $base; $P.AuthMode = 'local'; $P.OutDir = (Join-Path $tmp 'local'); $P.DoBackup = $false; $P.IncludeReadme = $false
    $u = 'ovpnbase-selftest'
    $P.Users = @(@{ Name = $u; Password = ''; IsNew = $true })
    $created.Certs += (Expand-OvpnUserTpl $P.UserCertTpl $u $year)
    $created.Secrets += $u
    $res = Invoke-OvpnBuild -Connection $c -P $P
    $sec = Get-RosFirst $c '/ppp/secret/print' -Query "?name=$u"
    Assert ($sec -and $sec['service'] -eq 'ovpn' -and $sec['profile'] -eq $P.UserProfile) "/ppp secret $u створено (service=ovpn, profile=$($sec['profile']))"
    $cr = @($res.Credentials | Where-Object { $_.New })
    Assert ($cr.Count -eq 1 -and $cr[0].Password.Length -ge 16) 'пароль згенеровано (16+ символів)'
    $udir = Join-Path $P.OutDir "users\$u"
    Assert ((Test-Path (Join-Path $udir "VPN-$year-$u.exe")) -and (Test-Path (Join-Path $udir "VPN-$year-$u-macOS.zip"))) 'архіви користувача в users\<логін>\'
    Assert ((Get-Content (Join-Path $P.OutDir 'users\credentials.csv') -Raw) -match [regex]::Escape($u)) 'credentials.csv (SaveCredentials=true)'
    $x2 = Join-Path $tmp 'x-local'
    [void](Invoke-SevenZip -Exe $sz.Exe -Arguments @('x', "-p$($P.ArchivePass)", "-o$x2", '-y', '--', (Join-Path $udir "VPN-$year-$u-macOS-AES.zip")) -WorkDir $tmp)
    $files = @(Get-ChildItem $x2 | ForEach-Object Name)
    Assert ($files.Count -eq 1 -and $files[0] -eq "VPN-$year-$u-macOS.ovpn") "zip містить лише .ovpn (README вимкнено): $($files -join ', ')"
    $mp = Get-Content (Join-Path $x2 $files[0]) -Raw
    $certBlock = [regex]::Match($mp, '(?s)<cert>(.+?)</cert>').Groups[1].Value
    $cn = Get-X509Cn (ConvertTo-X509 $certBlock)
    Assert ($cn -eq $u) "сертифікат у профілі: CN=$cn"
}
finally {
    Section 'Прибирання'
    foreach ($n in $created.Secrets) { $s = Get-RosFirst $c '/ppp/secret/print' -Query "?name=$n"; if ($s) { [void](Invoke-Ros $c '/ppp/secret/remove' -Arguments ([ordered]@{ '.id' = $s['.id'] })); "  - secret $n" } }
    foreach ($n in $created.Certs) { $x = Get-RosCert $c $n; if ($x) { [void](Invoke-Ros $c '/certificate/remove' -Arguments ([ordered]@{ '.id' = $x['.id'] })); "  - certificate $n" } }
    foreach ($n in $created.Servers) { $x = Get-RosFirst $c '/interface/ovpn-server/server/print' -Query "?name=$n"; if ($x) { [void](Invoke-Ros $c '/interface/ovpn-server/server/remove' -Arguments ([ordered]@{ '.id' = $x['.id'] })); "  - ovpn server $n" } }
    foreach ($id in $created.Rules) { try { [void](Invoke-Ros $c '/ip/firewall/filter/remove' -Arguments ([ordered]@{ '.id' = $id })); "  - firewall $id" } catch { } }
    foreach ($id in $created.Scripts) { try { [void](Invoke-Ros $c '/system/script/remove' -Arguments ([ordered]@{ '.id' = $id })); "  - script $id" } catch { } }
    foreach ($f in @(Invoke-Ros $c '/file/print' | Where-Object { $_['name'] -like 'ovpnx-*' -or $_['name'] -like "$tag*" -or $_['name'] -like 'ovpn-backup-*' })) { Remove-RosFile $c $f['name']; "  - file $($f['name'])" }
    $leftC = @(Invoke-Ros $c '/certificate/print' | Where-Object { $_['name'] -like "$tag*" }).Count
    $leftS = @(Invoke-Ros $c '/ppp/secret/print' -Proplist @('name') | Where-Object { $_['name'] -like 'ovpnbase-selftest*' }).Count
    $leftR = @(Invoke-Ros $c '/ip/firewall/filter/print' | Where-Object { $_['comment'] -like "$tag*" }).Count
    $leftV = @(Invoke-Ros $c '/interface/ovpn-server/server/print' | Where-Object { $_['name'] -like "$tag*" }).Count
    Assert ($leftC + $leftS + $leftR + $leftV -eq 0) "на роутері не лишилось тестових об'єктів (cert=$leftC secret=$leftS rule=$leftR server=$leftV)"
    Disconnect-RouterOs $c
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ''
if ($script:fail) { Write-Host "ПРОВАЛЕНО: $script:fail" -ForegroundColor Red; exit 1 } else { Write-Host 'Усі тести запису пройдено, роутер прибрано.' -ForegroundColor Green }
