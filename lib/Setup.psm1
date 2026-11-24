# Initial OpenVPN setup on a router that never had it (idempotent: every step skips existing objects).

$script:SetupStepDefs = @(
    @{ Key = 'setup.ca'; Title = 'Кореневий CA (наявний / створити) + trusted' }
    @{ Key = 'setup.cabackup'; Title = 'Backup CA (сертифікат + ключ) на ПК' }
    @{ Key = 'setup.srvcert'; Title = 'Серверний сертифікат (tls-server)' }
    @{ Key = 'setup.pool'; Title = 'IP-пул для клієнтів' }
    @{ Key = 'setup.profile'; Title = 'PPP-профіль' }
    @{ Key = 'setup.server'; Title = 'OpenVPN-сервер' }
    @{ Key = 'setup.firewall'; Title = 'Firewall: порт лише через список Zero Trust' }
    @{ Key = 'setup.radius'; Title = 'RADIUS для PPP' }
)
function Get-OvpnSetupStepDefs { return $script:SetupStepDefs }

function Get-OvpnSetupDefaults {
    param([Parameter(Mandatory)]$State)
    $id = ($State.Identity -replace '[^A-Za-z0-9_-]', '')
    if (-not $id) { $id = 'RT' }
    $src = $State.Servers | Select-Object -First 1
    $sc = if ($src) { Get-StateCert $State $src['certificate'] } else { $null }
    $caName = if ($sc -and $sc['ca']) { $sc['ca'] } else {
        $anyCa = $State.Certificates | Where-Object { (Test-RosTrue $_['authority']) -and (Test-RosTrue $_['private-key']) } | Select-Object -First 1
        if ($anyCa) { $anyCa['name'] } else { "CA-$id" }
    }
    $prof = if ($src) { $src['default-profile'] } else { 'VPN_POOL' }
    $p = $State.Profiles | Where-Object { $_['name'] -eq $prof } | Select-Object -First 1
    $poolName = if ($p -and $p['remote-address']) { $p['remote-address'] } else { 'OVPN_POOL' }
    $pool = $State.Pools | Where-Object { $_['name'] -eq $poolName } | Select-Object -First 1
    $port = if ($src) { [int]$src['port'] } else { Get-OvpnSuggestedPort $State }
    return [ordered]@{
        CaName = $caName; CaCn = $caName; CaKeySize = '4096'; CaDays = 3650; Country = 'UA'
        SrvCertName = $(if ($sc) { $sc['name'] } else { "OVPN-SRV-$id" }); SrvCn = $(if ($sc) { $sc['common-name'] } else { "OVPN-SRV-$id" }); SrvKeySize = '4096'; SrvDays = 3650
        PoolName = $poolName; PoolRange = $(if ($pool) { $pool['ranges'] } else { '10.8.0.2-10.8.0.254' })
        ProfileName = $prof; LocalAddress = $(if ($p -and $p['local-address']) { $p['local-address'] } else { $poolName }); DnsServer = ''
        ServerName = $(if ($src) { $src['name'] } else { 'ovpn-server1' }); Port = $port; Protocol = $(if ($src) { $src['protocol'] } else { 'tcp' })
        Cipher = 'aes256-gcm'; Auth = 'sha256'; UserAuth = 'pap'
        AddFirewall = $true; AllowList = $State.AllowList
        RadiusEnable = $false; RadiusAddress = ''; RadiusSecret = ''
    }
}

function Test-OvpnSetupParams {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][hashtable]$S)
    $e = New-Object System.Collections.Generic.List[string]
    foreach ($k in @('CaName', 'SrvCertName', 'PoolName', 'ProfileName', 'ServerName')) {
        if ($S[$k] -notmatch '^[A-Za-z0-9_.-]+$') { $e.Add("Некоректне значення $k='$($S[$k])'") }
    }
    $ca = Get-StateCert $State $S.CaName
    if ($ca -and -not (Test-RosTrue $ca['private-key'])) { $e.Add("CA '$($S.CaName)' існує, але без приватного ключа — підписувати неможливо") }
    if ($ca -and -not (Test-RosTrue $ca['authority'])) { $e.Add("'$($S.CaName)' існує, але це не CA") }
    if ($S.PoolRange -notmatch '^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$' -and -not ($State.Pools | Where-Object { $_['name'] -eq $S.PoolName })) { $e.Add('Діапазон пулу: формат 10.8.0.2-10.8.0.254') }
    $srv = $State.Servers | Where-Object { $_['name'] -eq $S.ServerName } | Select-Object -First 1
    if (-not $srv) {
        if ($S.Port -lt 1024 -or $S.Port -gt 65535) { $e.Add('Порт: 1024–65535') }
        else { $busy = Test-OvpnPortFree $State $S.Port; if ($busy) { $e.Add($busy) } }
        if ($S.Protocol -notin @('tcp', 'udp')) { $e.Add('Протокол: tcp або udp') }
    }
    if ($S.AddFirewall -and -not $srv) {
        $zt = Test-ZeroTrustPort -State $State -Port $S.Port -Protocol $S.Protocol
        if (-not $zt.DropRule) { $e.Add("Немає фінального drop для нових з'єднань з WAN — порт буде відкритий для всіх. Спочатку налаштуйте базовий firewall.") }
        if ($zt.OpenRule) { $e.Add("Порт уже відкритий для всіх правилом $($zt.OpenRule['.id'])") }
        if (@($State.WanInterfaces).Count -eq 0) { $e.Add('Не визначено WAN-інтерфейс (немає публічної IP на роутері)') }
    }
    if ($S.RadiusEnable) {
        $hasRad = @($State.Radius | Where-Object { $_['service'] -match '\bppp\b' }).Count -gt 0
        if (-not $hasRad) {
            $ip = $null
            if (-not [System.Net.IPAddress]::TryParse($S.RadiusAddress, [ref]$ip)) { $e.Add('Адреса RADIUS: IP') }
            if ($S.RadiusSecret.Length -lt 8) { $e.Add('RADIUS secret: мінімум 8 символів') }
        }
    }
    if ($S.CaBackupPass -and $S.CaBackupPass.Length -lt 8) { $e.Add('Паскей backup CA: мінімум 8 символів') }
    return $e.ToArray()
}

function Get-OvpnSetupPlan {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][hashtable]$S)
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("РОУТЕР $($State.Identity) — первинне налаштування (наявні об'єкти не змінюються):")
    $ca = Get-StateCert $State $S.CaName
    if ($ca) {
        $L.Add("  • CA $($S.CaName): є (до $($ca['invalid-after'])) — використовується")
        if (-not (Test-RosTrue $ca['trusted'])) { $L.Add("  • /certificate set $($S.CaName) trusted=yes") }
    } else {
        $L.Add("  • /certificate add name=$($S.CaName) common-name=$($S.CaCn) country=$($S.Country) key-size=$($S.CaKeySize) days-valid=$($S.CaDays) key-usage=key-cert-sign,crl-sign")
        $L.Add("  • /certificate sign $($S.CaName)   (самопідпис)  ;  set trusted=yes")
    }
    if ($S.CaBackupPass) { $L.Add("  • export-certificate $($S.CaName) type=pem export-passphrase=*** → $($S.OutDir)\ (тимчасові файли буде видалено)") }
    $sc = Get-StateCert $State $S.SrvCertName
    if ($sc) { $L.Add("  • серверний сертифікат $($S.SrvCertName): є — використовується") }
    else {
        $L.Add("  • /certificate add name=$($S.SrvCertName) common-name=$($S.SrvCn) key-size=$($S.SrvKeySize) days-valid=$($S.SrvDays) key-usage=digital-signature,key-encipherment,tls-server")
        $L.Add("  • /certificate sign $($S.SrvCertName) ca=$($S.CaName)")
    }
    if ($State.Pools | Where-Object { $_['name'] -eq $S.PoolName }) { $L.Add("  • пул $($S.PoolName): є") } else { $L.Add("  • /ip pool add name=$($S.PoolName) ranges=$($S.PoolRange)") }
    if ($State.Profiles | Where-Object { $_['name'] -eq $S.ProfileName }) { $L.Add("  • PPP-профіль $($S.ProfileName): є") }
    else { $L.Add("  • /ppp profile add name=$($S.ProfileName) local-address=$($S.LocalAddress) remote-address=$($S.PoolName) use-encryption=yes only-one=yes change-tcp-mss=yes$(if ($S.DnsServer) { " dns-server=$($S.DnsServer)" })") }
    $srv = $State.Servers | Where-Object { $_['name'] -eq $S.ServerName } | Select-Object -First 1
    if ($srv) { $L.Add("  • OpenVPN-сервер $($S.ServerName): є (порт $($srv['port'])) — без змін") }
    else {
        $L.Add("  • /interface ovpn-server server add name=$($S.ServerName) port=$($S.Port) protocol=$($S.Protocol) mode=ip certificate=$($S.SrvCertName) require-client-certificate=yes tls-version=only-1.2 cipher=$($S.Cipher) auth=$($S.Auth) default-profile=$($S.ProfileName) user-auth-method=$($S.UserAuth) disabled=no")
    }
    if ($S.AddFirewall) {
        $port = if ($srv) { [int]$srv['port'] } else { $S.Port }
        $proto = if ($srv) { $srv['protocol'] } else { $S.Protocol }
        $zt = Test-ZeroTrustPort -State $State -Port $port -Protocol $proto
        if ($zt.AllowRule) { $L.Add("  • firewall: порт $port уже дозволено через $($S.AllowList) ($($zt.AllowRule['.id']))") }
        else {
            $anyAllow = Find-OvpnAllowListRule -State $State
            if ($anyAllow) { $L.Add("  • /ip firewall filter set $($anyAllow['.id']) dst-port=$(Get-NewDstPort $anyAllow['dst-port'] -1 $port)   (наявне правило $($S.AllowList))") }
            else { $L.Add("  • /ip firewall filter add chain=input action=accept protocol=$proto dst-port=$port src-address-list=$($S.AllowList) in-interface=$(@($State.WanInterfaces)[0]) place-before=$(if ($zt.DropRule) { $zt.DropRule['.id'] } else { '?' })") }
            $L.Add("  • перевірка Zero Trust; при помилці — відкат")
        }
    } else { $L.Add('  • firewall: без змін') }
    if ($S.RadiusEnable) {
        $hasRad = @($State.Radius | Where-Object { $_['service'] -match '\bppp\b' }).Count -gt 0
        if (-not $hasRad) { $L.Add("  • /radius add address=$($S.RadiusAddress) secret=*** service=ppp authentication-port=1812 accounting-port=1813 timeout=1s") }
        else { $L.Add('  • RADIUS для ppp: є') }
        if (-not (Test-RosTrue (Get-RosVal $State.Aaa 'use-radius'))) { $L.Add('  • /ppp aaa set use-radius=yes accounting=yes') }
    }
    return $L.ToArray()
}

# Accept rule with src-address-list=<AllowList> on input/WAN with explicit dst-port (any port).
function Find-OvpnAllowListRule {
    param($State)
    foreach ($r in $State.Filter) {
        if ((Get-RosVal $r 'chain') -ne 'input' -or (Get-RosVal $r 'action') -ne 'accept') { continue }
        if ((Get-RosVal $r 'src-address-list') -ne $State.AllowList) { continue }
        if (Test-RosTrue (Get-RosVal $r 'disabled')) { continue }
        if (-not (Get-RosVal $r 'dst-port')) { continue }
        if (-not (Test-RuleAppliesToWanPublic $State $r)) { continue }
        return $r
    }
    return $null
}
function Test-RuleAppliesToWanPublic { param($State, $Rule)
    $ii = Get-RosVal $Rule 'in-interface'
    if ($ii -and -not $ii.StartsWith('!')) { return (@($State.WanInterfaces) -contains $ii) }
    return $true
}

function Invoke-OvpnSetup {
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][hashtable]$S)
    $c = $Connection
    $st = Get-RouterState -Connection $c -AllowList $S.AllowList
    $errs = Test-OvpnSetupParams -State $st -S $S
    if ($errs.Count) { throw ("Параметри не пройшли перевірку:`n - " + ($errs -join "`n - ")) }
    $res = @{ Files = @() }

    # CA
    Set-OvpnStep setup.ca run
    $ca = Get-StateCert $st $S.CaName
    if (-not $ca) {
        $ca = New-RosSignedCertificate -Connection $c -Name $S.CaName -CommonName $S.CaCn -Country $S.Country -KeySize $S.CaKeySize -Days $S.CaDays -Digest 'sha256' -KeyUsage 'key-cert-sign,crl-sign'
    }
    if (-not (Test-RosTrue $ca['trusted'])) { Set-RosCertTrusted -Connection $c -Name $S.CaName }
    Set-OvpnStep setup.ca ok "$($S.CaName), trusted"

    if ($S.CaBackupPass) {
        Set-OvpnStep setup.cabackup run
        $res.Files += Export-OvpnCaBackup -Connection $c -CaName $S.CaName -Passphrase $S.CaBackupPass -OutDir $S.OutDir
        Set-OvpnStep setup.cabackup ok $S.OutDir
    } else { Set-OvpnStep setup.cabackup skip }

    # server certificate
    Set-OvpnStep setup.srvcert run
    $sc = Get-StateCert $st $S.SrvCertName
    if (-not $sc) {
        $sc = New-RosSignedCertificate -Connection $c -Name $S.SrvCertName -CommonName $S.SrvCn -Country $S.Country -KeySize $S.SrvKeySize -Days $S.SrvDays -Digest 'sha256' `
            -KeyUsage 'digital-signature,key-encipherment,tls-server' -CaName $S.CaName
        Set-OvpnStep setup.srvcert ok 'створено'
    } else { Set-OvpnStep setup.srvcert skip 'вже є' }

    # pool
    if (-not ($st.Pools | Where-Object { $_['name'] -eq $S.PoolName })) {
        Set-OvpnStep setup.pool run
        [void](Invoke-Ros $c '/ip/pool/add' -Arguments ([ordered]@{ name = $S.PoolName; ranges = $S.PoolRange; comment = 'OvpnBase' }))
        Set-OvpnStep setup.pool ok $S.PoolRange
    } else { Set-OvpnStep setup.pool skip 'вже є' }

    # profile
    if (-not ($st.Profiles | Where-Object { $_['name'] -eq $S.ProfileName })) {
        Set-OvpnStep setup.profile run
        $a = [ordered]@{ name = $S.ProfileName; 'local-address' = $S.LocalAddress; 'remote-address' = $S.PoolName; 'use-encryption' = 'yes'; 'only-one' = 'yes'; 'change-tcp-mss' = 'yes'; comment = 'OvpnBase' }
        if ($S.DnsServer) { $a['dns-server'] = $S.DnsServer }
        [void](Invoke-Ros $c '/ppp/profile/add' -Arguments $a)
        Set-OvpnStep setup.profile ok
    } else { Set-OvpnStep setup.profile skip 'вже є' }

    # server
    $srv = $st.Servers | Where-Object { $_['name'] -eq $S.ServerName } | Select-Object -First 1
    $port = if ($srv) { [int]$srv['port'] } else { $S.Port }
    $proto = if ($srv) { $srv['protocol'] } else { $S.Protocol }
    $newSrvId = $null
    if (-not $srv) {
        Set-OvpnStep setup.server run
        $a = [ordered]@{
            name = $S.ServerName; port = $S.Port; protocol = $S.Protocol; mode = 'ip'; certificate = $S.SrvCertName
            'require-client-certificate' = 'yes'; 'tls-version' = 'only-1.2'; cipher = $S.Cipher; auth = $S.Auth
            'default-profile' = $S.ProfileName; 'user-auth-method' = $S.UserAuth; disabled = 'yes'
        }
        $ver = Get-RosVersion (Get-RosVal $st.Resource 'version')
        if ($ver -ge [version]'7.17') {
            [void](Invoke-Ros $c '/interface/ovpn-server/server/add' -Arguments $a)
        } else {
            $a.Remove('name')
            [void](Invoke-Ros $c '/interface/ovpn-server/server/set' -Arguments $a)
        }
        $srv = Get-RosFirst $c '/interface/ovpn-server/server/print' -Query "?name=$($S.ServerName)"
        if (-not $srv) { $srv = Get-RosFirst $c '/interface/ovpn-server/server/print' }
        $newSrvId = $srv['.id']
        Set-OvpnStep setup.server ok "$($S.ServerName) $($S.Protocol)/$($S.Port) (поки вимкнено)"
    } else { Set-OvpnStep setup.server skip 'вже є' }

    # firewall (Zero Trust)
    if ($S.AddFirewall) {
        Set-OvpnStep setup.firewall run
        $st.Filter = Invoke-Ros $c '/ip/firewall/filter/print'
        $zt = Test-ZeroTrustPort -State $st -Port $port -Protocol $proto
        $undo = $null
        if (-not $zt.AllowRule) {
            $anyAllow = Find-OvpnAllowListRule -State $st
            if ($anyAllow) {
                $old = $anyAllow['dst-port']
                [void](Invoke-Ros $c '/ip/firewall/filter/set' -Arguments ([ordered]@{ '.id' = $anyAllow['.id']; 'dst-port' = (Get-NewDstPort $old -1 $port) }))
                $undo = @{ Kind = 'set'; Id = $anyAllow['.id']; Old = $old }
            } else {
                $a = [ordered]@{
                    chain = 'input'; action = 'accept'; protocol = $proto; 'dst-port' = $port; 'src-address-list' = $S.AllowList
                    'in-interface' = @($st.WanInterfaces)[0]; comment = "OvpnBase: OpenVPN $port only via $($S.AllowList) (Zero Trust)"
                }
                if ($zt.DropRule) { $a['place-before'] = $zt.DropRule['.id'] }
                $newId = Invoke-RosRet $c '/ip/firewall/filter/add' -Arguments $a
                $undo = @{ Kind = 'add'; Id = $newId }
            }
            $st.Filter = Invoke-Ros $c '/ip/firewall/filter/print'
            $zt = Test-ZeroTrustPort -State $st -Port $port -Protocol $proto
            $bad = @($zt.Checks | Where-Object { $_.Status -eq 'FAIL' -or ($_.Status -eq 'WARN' -and $_.Name -like 'Доступ через*') })
            if ($bad.Count) {
                Write-OvpnLog -Level ERROR 'Zero Trust перевірка не пройшла — відкат firewall'
                if ($undo.Kind -eq 'set') { [void](Invoke-Ros $c '/ip/firewall/filter/set' -Arguments ([ordered]@{ '.id' = $undo.Id; 'dst-port' = $undo.Old })) }
                elseif ($undo.Id) { [void](Invoke-Ros $c '/ip/firewall/filter/remove' -Arguments ([ordered]@{ '.id' = $undo.Id })) }
                Set-OvpnStep setup.firewall fail $bad[0].Detail
                throw "Zero Trust: $($bad[0].Detail). Сервер залишено вимкненим."
            }
            Set-OvpnStep setup.firewall ok "порт $port лише через $($S.AllowList)"
        } else { Set-OvpnStep setup.firewall skip 'вже дозволено' }
    } else { Set-OvpnStep setup.firewall skip }

    if ($newSrvId) {
        [void](Invoke-Ros $c '/interface/ovpn-server/server/set' -Arguments ([ordered]@{ '.id' = $newSrvId; disabled = 'no' }))
        Write-OvpnLog -Level OK "OpenVPN-сервер $($S.ServerName) увімкнено"
    }

    # RADIUS
    if ($S.RadiusEnable) {
        Set-OvpnStep setup.radius run
        $hasRad = @($st.Radius | Where-Object { $_['service'] -match '\bppp\b' }).Count -gt 0
        if (-not $hasRad) {
            [void](Invoke-Ros $c '/radius/add' -Arguments ([ordered]@{ address = $S.RadiusAddress; secret = $S.RadiusSecret; service = 'ppp'; 'authentication-port' = 1812; 'accounting-port' = 1813; timeout = '1s'; comment = 'OvpnBase' }))
        }
        if (-not (Test-RosTrue (Get-RosVal $st.Aaa 'use-radius'))) {
            [void](Invoke-Ros $c '/ppp/aaa/set' -Arguments ([ordered]@{ 'use-radius' = 'yes'; accounting = 'yes' }))
        }
        Set-OvpnStep setup.radius ok
    } else { Set-OvpnStep setup.radius skip }
    return $res
}

Export-ModuleMember -Function Get-OvpnSetupStepDefs, Get-OvpnSetupDefaults, Test-OvpnSetupParams, Get-OvpnSetupPlan, Invoke-OvpnSetup, Find-OvpnAllowListRule
