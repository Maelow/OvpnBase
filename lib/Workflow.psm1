# Yearly build orchestration: validation, dry-run plan, execution, maintenance.

$script:StepDefs = @(
    @{ Key = 'backup'; Title = 'Backup конфігу роутера (/export)' }
    @{ Key = 'cert'; Title = 'Клієнтські сертифікати: створення та підпис' }
    @{ Key = 'export'; Title = 'Експорт сертифікатів, ключів та CA' }
    @{ Key = 'verify'; Title = 'Локальна перевірка ланцюжка та паскею' }
    @{ Key = 'users'; Title = 'Локальні користувачі /ppp secret (режим без RADIUS)' }
    @{ Key = 'server'; Title = 'Паралельний OpenVPN-сервер на новому порту' }
    @{ Key = 'firewall'; Title = 'Порт у правилі MGMT_Allow + перевірка Zero Trust' }
    @{ Key = 'schedule'; Title = 'Scheduler вимкнення старого сервера' }
    @{ Key = 'profiles'; Title = 'Генерація профілів Windows / macOS' }
    @{ Key = 'archives'; Title = 'Архіви: SFX exe, zip AES, zip ZipCrypto' }
    @{ Key = 'report'; Title = 'Звіт' }
)

function Get-OvpnStepDefs { return $script:StepDefs }

function Expand-OvpnUserTpl { param([string]$Tpl, [string]$User, $Year) return $Tpl.Replace('{user}', $User).Replace('{year}', "$Year") }

function New-OvpnSecret {
    param([int]$Length = 16)
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%+=@_-.'.ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] ($Length * 2)
    do {
        $rng.GetBytes($bytes)
        $s = -join (0..($Length - 1) | ForEach-Object { $chars[(([int]$bytes[2 * $_] -shl 8) -bor $bytes[2 * $_ + 1]) % $chars.Length] })
    } until ($s -cmatch '[A-Z]' -and $s -cmatch '[a-z]' -and $s -match '\d' -and $s -match '[^A-Za-z0-9]')
    return $s
}

# RADIUS → one shared certificate; local → certificate per user (CN = login).
function Get-OvpnIdentities {
    param([hashtable]$P)
    if ($P.AuthMode -eq 'local') {
        return @(foreach ($u in @($P.Users)) { @{ Login = $u.Name; CertName = (Expand-OvpnUserTpl $P.UserCertTpl $u.Name $P.Year); CertCn = $u.Name } })
    }
    return @(@{ Login = $null; CertName = $P.CertName; CertCn = $P.CertCn })
}

function Get-SourceServer {
    param($State, [string]$Name)
    return ($State.Servers | Where-Object { $_['name'] -eq $Name } | Select-Object -First 1)
}

function Test-OvpnParams {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][hashtable]$P)
    $e = New-Object System.Collections.Generic.List[string]
    $now = Get-Date
    if ($P.Year -lt $now.Year -or $P.Year -gt $now.Year + 2) { $e.Add("Рік $($P.Year) поза допустимим діапазоном") }
    if ($P.Days -lt 30 -or $P.Days -gt 1100) { $e.Add('Термін дії: 30–1100 днів') }
    $src = Get-SourceServer $State $P.SourceServer
    if (-not $src) { $e.Add("Не обрано поточний OpenVPN-сервер") }
    if ($P.Port -lt 1024 -or $P.Port -gt 65535) { $e.Add('Порт: 1024–65535') }
    elseif ($src -and [int]$src['port'] -ne $P.Port) {
        $existingNew = Get-SourceServer $State $P.NewServerName
        $busy = Test-OvpnPortFree $State $P.Port
        if ($busy -and -not ($existingNew -and [int]$existingNew['port'] -eq $P.Port)) { $e.Add($busy) }
        $zt = Test-ZeroTrustPort -State $State -Port $P.Port -Protocol $src['protocol']
        foreach ($c in ($zt.Checks | Where-Object { $_.Status -eq 'FAIL' })) { $e.Add("Zero Trust для нового порту: $($c.Detail)") }
        $ztOld = Test-ZeroTrustPort -State $State -Port ([int]$src['port']) -Protocol $src['protocol']
        if (-not $ztOld.AllowRule) { $e.Add("Не знайдено allow-правило з src-address-list=$($State.AllowList) для поточного порту $($src['port'])") }
        if (-not $P.NewServerName -or $P.NewServerName -notmatch '^[A-Za-z0-9_.-]+$') { $e.Add('Некоректне імʼя нового сервера') }
        elseif ($existingNew -and [int]$existingNew['port'] -ne $P.Port) { $e.Add("Сервер '$($P.NewServerName)' вже існує на порту $($existingNew['port'])") }
    }
    if (-not $P.VpnHost) { $e.Add('Вкажіть VPN-хост') }
    foreach ($h in @($P.VpnHost, $P.VpnHost2)) {
        if ($h -and $h -notmatch '^[A-Za-z0-9.-]+$') { $e.Add("Некоректний хост: $h") }
    }
    try { foreach ($r in $P.Routes) { [void](ConvertTo-OvpnRoute $r) } } catch { $e.Add($_.Exception.Message) }
    if (@($P.Routes | Where-Object { $_.Trim() }).Count -eq 0) { $e.Add('Вкажіть хоча б один маршрут') }
    if ($P.AuthMode -eq 'local') {
        $us = @($P.Users)
        if ($us.Count -eq 0) { $e.Add('Режим локальних користувачів: оберіть наявних або додайте нових') }
        if ($P.UserCertTpl -notmatch '\{user\}') { $e.Add('Шаблон імені сертифіката користувача має містити {user}') }
        $seen = @{}
        foreach ($u in $us) {
            $n = [string]$u.Name
            if ($n -notmatch '^[A-Za-z0-9._@-]{1,64}$') { $e.Add("Некоректний логін '$n' (латиниця, цифри, . _ @ -)"); continue }
            if ($seen.ContainsKey($n.ToLower())) { $e.Add("Логін '$n' вказано двічі") }
            $seen[$n.ToLower()] = 1
            $sec = $State.Secrets | Where-Object { $_['name'] -eq $n } | Select-Object -First 1
            if ($u.IsNew -and $sec) { $e.Add("Користувач '$n' вже існує на роутері — оберіть його у списку наявних") }
            if (-not $u.IsNew -and -not $sec) { $e.Add("Користувача '$n' немає на роутері") }
            if ($u.Password -and ($u.Password -match '["\s]' -or $u.Password.Length -lt 8)) { $e.Add("Пароль '$n': мінімум 8 символів, без пробілів і лапок") }
            $cn = Expand-OvpnUserTpl $P.UserCertTpl $n $P.Year
            if ($cn -notmatch '^[A-Za-z0-9_.@-]+$') { $e.Add("Некоректне ім'я сертифіката '$cn'") }
        }
        if (@($us | Where-Object { $_.IsNew }).Count -and -not ($State.Profiles | Where-Object { $_['name'] -eq $P.UserProfile })) { $e.Add("PPP-профіль '$($P.UserProfile)' не знайдено") }
    } else {
        if ($P.CertName -notmatch '^[A-Za-z0-9_.-]+$') { $e.Add('Некоректне імʼя сертифіката') }
        if ($P.CertCn -notmatch '^[A-Za-z0-9_.-]+$') { $e.Add('Некоректний CN') }
    }
    $existing = Get-StateCert $State $P.CertName
    if ($existing -and -not $existing['ca']) { } # unsigned template → will be signed
    if ($P.KeyPass.Length -lt 8) { $e.Add('Паскей ключа: мінімум 8 символів') }
    if ($P.KeyPass -match '["\s]') { $e.Add('Паскей ключа не може містити пробіли та лапки') }
    if ($P.ArchivePass.Length -lt 8) { $e.Add('Пароль архіву: мінімум 8 символів') }
    if ($P.ArchivePass -match '["\s]') { $e.Add('Пароль архіву не може містити пробіли та лапки') }
    if ($P.ArchivePass -eq $P.KeyPass) { $e.Add('Пароль архіву має відрізнятися від паскею ключа') }
    if ($P.Schedule) {
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParseExact("$($P.CutDate) $($P.CutTime)", 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$d)) { $e.Add('Дата/час переходу: формат yyyy-MM-dd і HH:mm') }
        elseif ($d -lt $now.AddHours(1)) { $e.Add('Дата переходу має бути в майбутньому') }
    }
    $ca = $null
    if ($src) { $sc = Get-StateCert $State $src['certificate']; if ($sc) { $ca = Get-StateCert $State $sc['ca'] } }
    if (-not $ca) { $e.Add('Не знайдено CA серверного сертифіката') }
    elseif (-not (Test-RosTrue $ca['private-key'])) { $e.Add("CA $($ca['name']) без приватного ключа — підпис неможливий") }
    else {
        $caExp = ConvertFrom-RosDate $ca['invalid-after']
        if ($caExp -and $now.AddDays($P.Days) -gt $caExp) { $e.Add("Термін сертифіката виходить за термін CA ($($ca['invalid-after']))") }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $P.ToolsDir '7z.exe'))) { $e.Add("Немає 7-Zip у $($P.ToolsDir)") }
    return $e.ToArray()
}

function Get-OvpnContext {
    param($State, [hashtable]$P)
    $src = Get-SourceServer $State $P.SourceServer
    $sc = Get-StateCert $State $src['certificate']
    $ctx = @{
        Src = $src; SrcPort = [int]$src['port']; Protocol = $src['protocol']
        ServerCert = $sc; CaName = $sc['ca']; ServerCn = $sc['common-name']
        PortChange = ([int]$src['port'] -ne $P.Port)
        AllowRule = $null
    }
    if ($ctx.PortChange) { $ctx.AllowRule = (Test-ZeroTrustPort -State $State -Port $ctx.SrcPort -Protocol $ctx.Protocol).AllowRule }
    return $ctx
}

function Get-NewDstPort {
    param([string]$Old, [int]$SrcPort, [int]$NewPort)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($x in $Old.Split(',')) { if ($x.Trim()) { $parts.Add($x.Trim()) } }
    if ($parts -contains "$NewPort") { return $Old }
    $i = $parts.IndexOf("$SrcPort")
    if ($i -ge 0) { $parts.Insert($i + 1, "$NewPort") } else { $parts.Insert(0, "$NewPort") }
    return ($parts -join ',')
}

function Get-CutoverScript {
    param([string]$RuleId, [int]$OldPort, [string]$OldServer, [string]$SchedName)
    return @"
:local rid [/ip firewall filter find where .id=$RuleId]
:local old "$OldPort"
:local p [/ip firewall filter get `$rid dst-port]
:local out ""
:foreach x in=[:toarray `$p] do={ :if ([:tostr `$x] != `$old) do={ :if (`$out = "") do={ :set out [:tostr `$x] } else={ :set out (`$out . "," . [:tostr `$x]) } } }
:if (`$out != "") do={ /ip firewall filter set `$rid dst-port=`$out }
/interface ovpn-server server disable [find name="$OldServer"]
:log warning "OVPN cutover: $OldServer disabled, port $OldPort removed from rule $RuleId"
/system scheduler remove [find name="$SchedName"]
"@
}

function Get-OvpnBuildPlan {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][hashtable]$P)
    $x = Get-OvpnContext $State $P
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("РОУТЕР $($State.Identity) — зміни:")
    if ($P.DoBackup) { $L.Add("  • /export file=ovpn-backup-… → out\$($P.Year)\ (тимчасовий файл на роутері буде видалено)") }
    $ids = @(Get-OvpnIdentities -P $P)
    if ($P.AuthMode -eq 'local') { $L.Add("  • режим: локальні користувачі — окремий сертифікат (CN=логін) і архіви на кожного ($($ids.Count))") }
    else { $L.Add('  • режим: RADIUS — один спільний сертифікат для всіх') }
    foreach ($id in $ids) {
        $ex = Get-StateCert $State $id.CertName
        if ($ex -and $ex['ca']) { $L.Add("  • сертифікат $($id.CertName) вже існує — буде використано наявний (без змін)"); continue }
        $L.Add("  • /certificate add name=$($id.CertName) common-name=$($id.CertCn) country=$($P.Country) key-size=$($P.KeySize) days-valid=$($P.Days) key-usage=tls-client digest-algorithm=$($P.Digest)")
        $L.Add("  • /certificate sign $($id.CertName) ca=$($x.CaName)" + $(if ($P.KeySize -match '^(8192|16384)$') { '   (RSA ' + $P.KeySize + ' — може тривати хвилини)' } else { '' }))
    }
    if ($P.KeySize -eq '16384' -and $ids.Count -gt 2) { $L.Add("  ⚠ RSA 16384 × $($ids.Count) користувачів: підпис може тривати годинами — розгляньте 4096 / P-384") }
    $L.Add("  • export-certificate ($($ids.Count) шт.) type=pem export-passphrase=*** та CA $($x.CaName) (тимчасові файли буде видалено)")
    if ($P.AuthMode -eq 'local') {
        foreach ($u in @($P.Users | Where-Object { $_.IsNew })) { $L.Add("  • /ppp secret add name=$($u.Name) password=*** service=ovpn profile=$($P.UserProfile)" + $(if (-not $u.Password) { '   (пароль буде згенеровано)' } else { '' })) }
        $old = @($P.Users | Where-Object { -not $_.IsNew })
        if ($old.Count) { $L.Add("  • наявні користувачі ($($old.Count)): /ppp secret без змін, лише нові сертифікати") }
    }
    if ($x.PortChange) {
        $ns = Get-SourceServer $State $P.NewServerName
        if ($ns) { $L.Add("  • сервер $($P.NewServerName) вже існує на порту $($ns['port']) — без змін") }
        else {
            $L.Add("  • /interface ovpn-server server add copy-from=$($P.SourceServer) name=$($P.NewServerName) port=$($P.Port) disabled=yes")
        }
        $old = $x.AllowRule['dst-port']
        $new = Get-NewDstPort $old $x.SrcPort $P.Port
        if ($new -ne $old) {
            $L.Add("  • /ip firewall filter set $($x.AllowRule['.id']) dst-port=$new   (було: $old; src-address-list=$($State.AllowList), «$($x.AllowRule['comment'])»)")
        }
        $L.Add("  • перевірка Zero Trust порту $($P.Port); при помилці — відкат dst-port")
        if (-not $ns) { $L.Add("  • /interface ovpn-server server enable $($P.NewServerName)") }
        $L.Add("  • $($P.SourceServer) (порт $($x.SrcPort)) продовжує працювати")
        if ($P.Schedule) {
            $L.Add("  • /system scheduler add name=ovpn-cutover-$($P.Year) $($P.CutDate) $($P.CutTime): вимкнути $($P.SourceServer), прибрати порт $($x.SrcPort) з правила $($x.AllowRule['.id'])")
        }
    } else {
        $L.Add("  • порт не змінюється ($($P.Port)) — сервер і firewall без змін")
    }
    $L.Add('')
    $L.Add("ЛОКАЛЬНО (out\$($P.Year)):")
    $hosts = (@($P.VpnHost, $P.VpnHost2) | Where-Object { $_ }) -join ', '
    $L.Add("  • профілі VPN-$($P.Year)-Windows.ovpn / VPN-$($P.Year)-macOS.ovpn: remote $hosts порт $($P.Port)/$($x.Protocol), $(if ($P.Modern) { 'сучасні опції' } else { 'як у попередньому році' })")
    $L.Add("  • маршрути: $(($P.Routes | Where-Object { $_.Trim() }) -join ', ')")
    if ($P.AuthMode -eq 'local') {
        $L.Add("  • users\<логін>\: VPN-$($P.Year)-<логін>.exe, -macOS-AES.zip, -macOS.zip — для кожного з $($ids.Count) користувачів")
        if ($P.SaveCredentials) { $L.Add('  • users\credentials.csv з паролями НОВИХ користувачів (відкритий текст!)') }
    } else {
        $L.Add("  • VPN-$($P.Year).exe (7z SFX AES-256, приховані імена), VPN-$($P.Year)-macOS-AES.zip, VPN-$($P.Year)-macOS.zip (ZipCrypto)")
    }
    $L.Add("  • вміст архівів: лише .ovpn" + $(if ($P.IncludeReadme) { ' + README з інструкцією' + $(if ($P.PortalUrl) { " (портал $($P.PortalUrl))" } else { '' }) } else { '' }))
    if ($P.DeleteOpen) { $L.Add('  • незашифровані .ovpn буде видалено після пакування') }
    return $L.ToArray()
}

function New-RandomMac {
    $b = New-Object byte[] 5
    (New-Object System.Random).NextBytes($b)
    return '02:' + (($b | ForEach-Object { $_.ToString('X2') }) -join ':')
}

function Write-TextFile {
    param([string]$Path, [string]$Text, [switch]$Bom)
    $enc = New-Object System.Text.UTF8Encoding ([bool]$Bom)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Invoke-OvpnBuild {
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][hashtable]$P)
    $c = $Connection
    $result = @{ Files = @(); Warnings = @(); Certificate = $null; Fingerprint = $null }
    $outDir = $P.OutDir
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $profDir = Join-Path $outDir 'profiles'
    New-Item -ItemType Directory -Force -Path $profDir | Out-Null

    Write-OvpnLog -Level STEP "Оновлюю стан роутера…"
    $st = Get-RouterState -Connection $c -AllowList $P.AllowList
    $errs = Test-OvpnParams -State $st -P $P
    if ($errs.Count) { throw ("Параметри не пройшли перевірку:`n - " + ($errs -join "`n - ")) }
    $x = Get-OvpnContext $st $P
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    # 1. backup
    if ($P.DoBackup) {
        Set-OvpnStep backup run
        $fn = "ovpn-backup-$stamp"
        try {
            [void](Invoke-Ros $c '/export' -Arguments ([ordered]@{ file = $fn }) -TimeoutMs 180000)
            $txt = Read-RosFile $c "$fn.rsc"
            $bpath = Join-Path $outDir "backup-$($st.Identity)-$stamp.rsc"
            [System.IO.File]::WriteAllBytes($bpath, (Get-RosEncoding).GetBytes($txt))
            $result.Files += $bpath
            Set-OvpnStep backup ok (Split-Path -Leaf $bpath)
        } finally { try { Remove-RosFile $c "$fn.rsc" } catch { } }
    } else { Set-OvpnStep backup skip }

    $ids = @(Get-OvpnIdentities -P $P)
    $result.Credentials = @()

    # 2. certificates
    $i = 0
    foreach ($id in $ids) {
        $i++
        Set-OvpnStep cert run "[$i/$($ids.Count)] $($id.CertName), $($P.KeySize)"
        $id.Cert = New-OvpnClientCertificate -Connection $c -Name $id.CertName -CommonName $id.CertCn -Country $P.Country -KeySize $P.KeySize -Days $P.Days -Digest $P.Digest -CaName $x.CaName
    }
    $result.Certificate = $ids[0].Cert
    Set-OvpnStep cert ok "$($ids.Count) шт., діє до $($ids[0].Cert['invalid-after'])"

    # 3. export
    Set-OvpnStep export run
    $caPem = (Export-RosCertificatePem -Connection $c -Name $x.CaName).Cert
    foreach ($id in $ids) { $id.Pem = Export-RosCertificatePem -Connection $c -Name $id.CertName -Passphrase $P.KeyPass }
    Set-OvpnStep export ok "$($ids.Count) × (сертифікат + зашифрований ключ), CA"

    # 4. verify
    Set-OvpnStep verify run
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $warned = $false
    foreach ($id in $ids) {
        $vc = Test-OvpnCertificateLocal -CertPem $id.Pem.Cert -KeyPem $id.Pem.Key -CaPem $caPem -Passphrase $P.KeyPass -ExpectedCn $id.CertCn
        foreach ($v in $vc) { Write-OvpnLog -Level $(switch ($v.Status) { 'OK' { 'OK' } 'FAIL' { 'ERROR' } 'WARN' { 'WARN' } default { 'INFO' } }) "$($id.CertName) · $($v.Name): $($v.Detail)" }
        $vf = @($vc | Where-Object { $_.Status -eq 'FAIL' })
        if ($vf.Count) { Set-OvpnStep verify fail "$($id.CertName): $($vf[0].Detail)"; throw "Локальна перевірка $($id.CertName) не пройшла: $($vf[0].Detail)" }
        $id.X509 = ConvertTo-X509 $id.Pem.Cert
        $id.Fingerprint = (($sha.ComputeHash($id.X509.RawData) | ForEach-Object { $_.ToString('X2') }) -join ':')
        $vw = @($vc | Where-Object { $_.Status -eq 'WARN' })
        if ($vw.Count -and -not $warned) { $result.Warnings += $vw.Detail; $warned = $true }
    }
    $result.Fingerprint = $ids[0].Fingerprint
    $x509 = $ids[0].X509
    if ($warned) { Set-OvpnStep verify warn ($result.Warnings[0]) } else { Set-OvpnStep verify ok "$($ids.Count) шт." }

    # 4b. local users (after all certificates succeeded)
    if ($P.AuthMode -eq 'local') {
        Set-OvpnStep users run
        $nNew = 0
        foreach ($u in @($P.Users)) {
            if ($u.IsNew) {
                $pw = if ($u.Password) { $u.Password } else { New-OvpnSecret 16 }
                [void](Invoke-Ros $c '/ppp/secret/add' -Arguments ([ordered]@{ name = $u.Name; password = $pw; service = 'ovpn'; profile = $P.UserProfile; comment = "OvpnBase $($P.Year)" }))
                $result.Credentials += [pscustomobject]@{ User = $u.Name; Password = $pw; New = $true }
                $nNew++
            } else {
                $result.Credentials += [pscustomobject]@{ User = $u.Name; Password = ''; New = $false }
            }
        }
        Set-OvpnStep users ok "нових: $nNew, наявних: $(@($P.Users).Count - $nNew)"
    } else { Set-OvpnStep users skip 'RADIUS' }

    # 5-6. server + firewall
    if ($x.PortChange) {
        Set-OvpnStep server run "$($P.NewServerName):$($P.Port)"
        $ns = Get-SourceServer $st $P.NewServerName
        $created = $false
        if (-not $ns) {
            [void](Invoke-Ros $c '/interface/ovpn-server/server/add' -Arguments ([ordered]@{
                        'copy-from' = $x.Src['.id']; name = $P.NewServerName; port = $P.Port; 'mac-address' = (New-RandomMac); disabled = 'yes'
                        comment = "OVPN $($P.Year) (створено OvpnBase $stamp)"
                    }))
            $ns = Get-RosFirst $c '/interface/ovpn-server/server/print' -Query "?name=$($P.NewServerName)"
            if (-not $ns) { throw "Сервер $($P.NewServerName) не створився" }
            $created = $true
            foreach ($k in @('certificate', 'require-client-certificate', 'tls-version', 'cipher', 'auth', 'default-profile', 'protocol', 'mode')) {
                if ("$($ns[$k])" -ne "$($x.Src[$k])") { Write-OvpnLog -Level WARN "Новий сервер: $k=$($ns[$k]) відрізняється від $($x.Src[$k])" }
            }
        }
        Set-OvpnStep server ok $(if ($created) { 'створено (поки вимкнено)' } else { 'вже існує' })

        Set-OvpnStep firewall run
        $rule = $x.AllowRule
        $oldDp = $rule['dst-port']
        $newDp = Get-NewDstPort $oldDp $x.SrcPort $P.Port
        if ($newDp -ne $oldDp) {
            [void](Invoke-Ros $c '/ip/firewall/filter/set' -Arguments ([ordered]@{ '.id' = $rule['.id']; 'dst-port' = $newDp }))
        }
        $st.Filter = Invoke-Ros $c '/ip/firewall/filter/print'
        $zt = Test-ZeroTrustPort -State $st -Port $P.Port -Protocol $x.Protocol
        $bad = @($zt.Checks | Where-Object { $_.Status -eq 'FAIL' -or ($_.Status -eq 'WARN' -and $_.Name -like 'Доступ через*') })
        if ($bad.Count) {
            if ($newDp -ne $oldDp) {
                Write-OvpnLog -Level ERROR "Zero Trust перевірка не пройшла — відкат dst-port"
                [void](Invoke-Ros $c '/ip/firewall/filter/set' -Arguments ([ordered]@{ '.id' = $rule['.id']; 'dst-port' = $oldDp }))
            }
            Set-OvpnStep firewall fail $bad[0].Detail
            throw "Zero Trust: $($bad[0].Detail). Новий сервер залишено вимкненим."
        }
        Set-OvpnStep firewall ok "правило $($rule['.id']) dst-port=$newDp"
        if (Test-RosTrue $ns['disabled']) {
            [void](Invoke-Ros $c '/interface/ovpn-server/server/set' -Arguments ([ordered]@{ '.id' = $ns['.id']; disabled = 'no' }))
            Write-OvpnLog -Level OK "Сервер $($P.NewServerName) увімкнено на порту $($P.Port)"
        }

        if ($P.Schedule) {
            Set-OvpnStep schedule run
            $sn = "ovpn-cutover-$($P.Year)"
            $ex = Get-RosFirst $c '/system/scheduler/print' -Query "?name=$sn"
            if ($ex) { [void](Invoke-Ros $c '/system/scheduler/remove' -Arguments ([ordered]@{ '.id' = $ex['.id'] })) }
            $ver = Get-RosVersion (Get-RosVal $st.Resource 'version')
            $d = [datetime]::ParseExact($P.CutDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            $sd = if ($ver -ge [version]'7.10') { $d.ToString('yyyy-MM-dd') } else { $d.ToString('MMM/dd/yyyy', [Globalization.CultureInfo]::InvariantCulture).ToLower() }
            [void](Invoke-Ros $c '/system/scheduler/add' -Arguments ([ordered]@{
                        name = $sn; 'start-date' = $sd; 'start-time' = "$($P.CutTime):00"; interval = '0s'
                        policy = 'read,write,test'; comment = "OvpnBase: вимкнути $($P.SourceServer), прибрати порт $($x.SrcPort)"
                        'on-event' = (Get-CutoverScript -RuleId $rule['.id'] -OldPort $x.SrcPort -OldServer $P.SourceServer -SchedName $sn)
                    }))
            Set-OvpnStep schedule ok "$sn $($P.CutDate) $($P.CutTime)"
        } else { Set-OvpnStep schedule skip }
    } else {
        Set-OvpnStep server skip 'порт не змінюється'
        Set-OvpnStep firewall skip
        Set-OvpnStep schedule skip
    }

    # 7. profiles
    Set-OvpnStep profiles run
    $hosts = @(@($P.VpnHost, $P.VpnHost2) | Where-Object { $_ })
    foreach ($id in $ids) {
        $id.Dir = if ($id.Login) { Join-Path $outDir "users\$($id.Login)" } else { $outDir }
        $id.ProfDir = Join-Path $id.Dir 'profiles'
        New-Item -ItemType Directory -Force -Path $id.ProfDir | Out-Null
        $id.Base = if ($id.Login) { "VPN-$($P.Year)-$($id.Login)" } else { "VPN-$($P.Year)" }
        $id.Files = @{}
        foreach ($pl in @('Windows', 'macOS')) {
            $name = "$($id.Base)-$pl.ovpn"
            $fname = if ($id.Login) { "$($P.FriendlyName) ($($id.Login))" } else { $P.FriendlyName }
            $txt = New-OvpnProfileText -Platform $pl -Hosts $hosts -Port $P.Port -Protocol $x.Protocol -CaPem $caPem -CertPem $id.Pem.Cert -KeyPem $id.Pem.Key `
                -FriendlyName $fname -Routes $P.Routes -ServerCn $x.ServerCn -Modern $P.Modern
            $path = Join-Path $id.ProfDir $name
            Write-TextFile -Path $path -Text $txt
            $id.Files[$pl] = @($path)
            if ($P.IncludeReadme) {
                $readme = Join-Path $id.ProfDir "README-$pl.txt"
                Write-TextFile -Path $readme -Text (New-OvpnReadme -Platform $pl -ProfileName $name -Year $P.Year -PortalUrl $P.PortalUrl -ValidTo ("{0:yyyy-MM-dd}" -f $id.X509.NotAfter)) -Bom
                $id.Files[$pl] += $readme
            }
        }
    }
    Set-OvpnStep profiles ok "$($ids.Count * 2) профілів (Windows + macOS)"

    # 8. archives
    Set-OvpnStep archives run
    $sz = Get-SevenZip -ToolsDir $P.ToolsDir
    foreach ($id in $ids) {
        $a1 = New-OvpnArchive -SevenZip $sz -Kind Sfx -OutFile (Join-Path $id.Dir "$($id.Base).exe") -Files $id.Files['Windows'] -WorkDir $id.ProfDir -Password $P.ArchivePass
        $a2 = New-OvpnArchive -SevenZip $sz -Kind ZipAes -OutFile (Join-Path $id.Dir "$($id.Base)-macOS-AES.zip") -Files $id.Files['macOS'] -WorkDir $id.ProfDir -Password $P.ArchivePass
        $a3 = New-OvpnArchive -SevenZip $sz -Kind ZipCrypto -OutFile (Join-Path $id.Dir "$($id.Base)-macOS.zip") -Files $id.Files['macOS'] -WorkDir $id.ProfDir -Password $P.ArchivePass
        $result.Files += @($a1.FullName, $a2.FullName, $a3.FullName)
        if ($P.DeleteOpen) { Remove-Item -LiteralPath $id.ProfDir -Recurse -Force }
        else { $result.Files += @($id.Files['Windows'][0], $id.Files['macOS'][0]) }
    }
    if ($P.DeleteOpen) { Write-OvpnLog 'Незашифровані профілі видалено' }
    if ($P.AuthMode -eq 'local' -and $P.SaveCredentials) {
        $csv = Join-Path $outDir 'users\credentials.csv'
        $lines = @('login;password;archive') + @($result.Credentials | Where-Object { $_.New } | ForEach-Object { "$($_.User);$($_.Password);VPN-$($P.Year)-$($_.User).exe" })
        Write-TextFile -Path $csv -Text (($lines -join "`r`n") + "`r`n") -Bom
        $result.Files += $csv
        Write-OvpnLog -Level WARN "Паролі нових користувачів збережено у $csv (відкритий текст) — видаліть після роздачі"
    }
    Set-OvpnStep archives ok "$($ids.Count * 3) архівів"

    # 9. report
    Set-OvpnStep report run
    $rep = New-Object System.Collections.Generic.List[string]
    $rep.Add("OVPN $($P.Year) — звіт ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))")
    $rep.Add("Роутер: $($st.Identity) ($($c.Address)), RouterOS $(Get-RosVal $st.Resource 'version')")
    $rep.Add("Режим: $(if ($P.AuthMode -eq 'local') { 'локальні користувачі (/ppp secret), сертифікат на кожного' } else { 'RADIUS, спільний сертифікат' })")
    foreach ($id in $ids) {
        $rep.Add("Сертифікат: $($id.CertName) CN=$($id.CertCn) $($P.KeySize)/$($P.Digest), діє $("{0:yyyy-MM-dd}" -f $id.X509.NotBefore) — $("{0:yyyy-MM-dd}" -f $id.X509.NotAfter)")
        $rep.Add("  SHA256: $($id.Fingerprint)")
    }
    if ($P.AuthMode -eq 'local') { $rep.Add("Користувачі: $((@($result.Credentials) | ForEach-Object { $_.User + $(if ($_.New) { ' (новий)' } else { '' }) }) -join ', ')") }
    $rep.Add("CA: $($x.CaName); сервер: $($x.ServerCn)")
    $rep.Add("Хост(и): $($hosts -join ', '); порт $($P.Port)/$($x.Protocol)")
    if ($x.PortChange) {
        $rep.Add("Новий сервер: $($P.NewServerName):$($P.Port); старий $($P.SourceServer):$($x.SrcPort) працює" + $(if ($P.Schedule) { " до $($P.CutDate) $($P.CutTime) (scheduler ovpn-cutover-$($P.Year))" } else { ' (вимкнути вручну)' }))
        $rep.Add("Firewall: правило $($x.AllowRule['.id']) src-address-list=$($st.AllowList)")
    }
    $rep.Add("Маршрути: $(($P.Routes | Where-Object { $_.Trim() }) -join ', ')")
    $rep.Add("Профіль: $(if ($P.Modern) { 'сучасний (remote-cert-tls, verify-x509-name, data-ciphers, tls-version-min 1.2)' } else { 'сумісний з попереднім' })")
    $rep.Add('Файли:')
    foreach ($f in $result.Files) { if (Test-Path -LiteralPath $f) { $rep.Add(("  {0}  {1:N0} байт" -f (Split-Path -Leaf $f), (Get-Item -LiteralPath $f).Length)) } }
    foreach ($w in $result.Warnings) { $rep.Add("Попередження: $w") }
    $rep.Add('Паролі в цьому звіті не зберігаються.')
    $rp = Join-Path $outDir 'report.txt'
    Write-TextFile -Path $rp -Text (($rep -join "`r`n") + "`r`n") -Bom
    $result.Files += $rp
    Set-OvpnStep report ok
    return $result
}

# ---------------------------------------------------------------- maintenance
function Set-OvpnServerEnabled {
    param($Connection, [string]$Name, [bool]$Enabled)
    $s = Get-RosFirst $Connection '/interface/ovpn-server/server/print' -Query "?name=$Name"
    if (-not $s) { throw "Сервер $Name не знайдено" }
    [void](Invoke-Ros $Connection '/interface/ovpn-server/server/set' -Arguments ([ordered]@{ '.id' = $s['.id']; disabled = $(if ($Enabled) { 'no' } else { 'yes' }) }))
}

function Remove-OvpnPortFromAllowRule {
    param($Connection, $State, [int]$Port, [string]$Protocol = 'tcp')
    $zt = Test-ZeroTrustPort -State $State -Port $Port -Protocol $Protocol
    $rule = $zt.AllowRule
    if (-not $rule) { throw "Порт $Port не знайдено в allow-правилі $($State.AllowList)" }
    $parts = @($rule['dst-port'].Split(',') | Where-Object { $_.Trim() -and $_.Trim() -ne "$Port" })
    if ($parts.Count -eq 0) { throw "У правилі $($rule['.id']) залишився б порожній dst-port — змініть вручну" }
    $new = $parts -join ','
    [void](Invoke-Ros $Connection '/ip/firewall/filter/set' -Arguments ([ordered]@{ '.id' = $rule['.id']; 'dst-port' = $new }))
    return "$($rule['.id']): $($rule['dst-port']) → $new"
}

function Remove-OvpnScheduler {
    param($Connection, [string]$Name)
    $s = Get-RosFirst $Connection '/system/scheduler/print' -Query "?name=$Name"
    if (-not $s) { throw "Scheduler $Name не знайдено" }
    [void](Invoke-Ros $Connection '/system/scheduler/remove' -Arguments ([ordered]@{ '.id' = $s['.id'] }))
}

Export-ModuleMember -Function Get-OvpnStepDefs, Get-OvpnIdentities, Expand-OvpnUserTpl, New-OvpnSecret, Test-OvpnParams, Get-OvpnBuildPlan, Invoke-OvpnBuild, Get-NewDstPort, Get-CutoverScript,
    Set-OvpnServerEnabled, Remove-OvpnPortFromAllowRule, Remove-OvpnScheduler
