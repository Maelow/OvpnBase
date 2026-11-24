# Router state collection and diagnostics (read-only).

# ---------------------------------------------------------------- helpers
function New-OvpnCheck {
    param([string]$Group, [string]$Name, [ValidateSet('OK', 'WARN', 'FAIL', 'INFO')][string]$Status, [string]$Detail = '', [string]$Fix = '', [switch]$Critical)
    $icon = switch ($Status) { 'OK' { [string][char]0x2714 } 'WARN' { [string][char]0x26A0 } 'FAIL' { [string][char]0x2716 } default { [string][char]0x2139 } }
    [pscustomobject]@{ Icon = $icon; Status = $Status; Group = $Group; Name = $Name; Detail = $Detail; Fix = $Fix; Critical = [bool]$Critical }
}

function Get-RosVal {
    param($Row, [string]$Key, $Default = '')
    if ($null -eq $Row) { return $Default }
    if ($Row.Contains($Key)) { return $Row[$Key] }
    return $Default
}

function Test-RosTrue { param($Value) return ($Value -eq 'true' -or $Value -eq 'yes') }

function ConvertFrom-RosDate {
    param([string]$Value)
    if (-not $Value) { return $null }
    $fmts = @('yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd', 'MMM/dd/yyyy HH:mm:ss', 'MMM/dd/yyyy')
    foreach ($f in $fmts) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($Value, $f, [Globalization.CultureInfo]::InvariantCulture, 'AllowWhiteSpaces', [ref]$d)) { return $d }
    }
    return $null
}

function Get-RosVersion {
    param([string]$Value)
    if ($Value -match '^(\d+)\.(\d+)(?:\.(\d+))?') {
        $p = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
        return New-Object version ([int]$Matches[1]), ([int]$Matches[2]), $p
    }
    return New-Object version 0, 0
}

# '52431,8291,8728-8729' contains 8728 ?
function Test-PortInSpec {
    param([string]$Spec, [int]$Port)
    if (-not $Spec) { return $true }
    $neg = $false
    if ($Spec.StartsWith('!')) { $neg = $true; $Spec = $Spec.Substring(1) }
    $hit = $false
    foreach ($part in $Spec.Split(',')) {
        $p = $part.Trim()
        if ($p -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { $hit = $true } }
        elseif ($p -match '^\d+$') { if ([int]$p -eq $Port) { $hit = $true } }
    }
    if ($neg) { return -not $hit }
    return $hit
}

function ConvertTo-IpUInt { param([string]$Ip)
    $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    return ([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3]
}

function Test-IpInCidr {
    param([string]$Ip, [string]$Cidr)
    try {
        $parts = $Cidr.Split('/')
        $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
        if ($parts[0] -match '-') { return $false }
        $mask = if ($bits -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl (32 - $bits)) }
        return (((ConvertTo-IpUInt $Ip) -band $mask) -eq ((ConvertTo-IpUInt $parts[0]) -band $mask))
    } catch { return $false }
}

function Test-PrivateIp {
    param([string]$Ip)
    foreach ($n in @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16')) {
        if (Test-IpInCidr $Ip $n) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------- state
function Get-RouterState {
    param([Parameter(Mandatory)]$Connection, [string]$AllowList = 'MGMT_Allow')
    $c = $Connection
    $st = @{}
    $st.CollectedAt = Get-Date
    $st.AllowList = $AllowList
    $st.ApiUser = $c.User
    $st.Resource = Get-RosFirst $c '/system/resource/print'
    $st.Identity = Get-RosVal (Get-RosFirst $c '/system/identity/print') 'name'
    $st.Clock = Get-RosFirst $c '/system/clock/print'
    $st.Ntp = $null; try { $st.Ntp = Get-RosFirst $c '/system/ntp/client/print' } catch { }
    $st.Servers = Invoke-Ros $c '/interface/ovpn-server/server/print'
    $st.Sessions = Invoke-Ros $c '/ppp/active/print' -Query '?service=ovpn'
    $st.Certificates = Invoke-Ros $c '/certificate/print'
    $st.Profiles = Invoke-Ros $c '/ppp/profile/print'
    # без паролів: лише несекретні поля
    $st.Secrets = Invoke-Ros $c '/ppp/secret/print' -Proplist @('.id', 'name', 'service', 'profile', 'disabled', 'comment', 'last-logged-out')
    $st.Pools = Invoke-Ros $c '/ip/pool/print'
    $st.Aaa = Get-RosFirst $c '/ppp/aaa/print'
    $st.Radius = Invoke-Ros $c '/radius/print'
    $st.RadiusMonitor = @{}
    foreach ($r in $st.Radius) {
        try { $st.RadiusMonitor[$r['.id']] = Get-RosFirst $c '/radius/monitor' -Query @("=.id=$($r['.id'])", '=once=') } catch { }
    }
    $st.Filter = Invoke-Ros $c '/ip/firewall/filter/print'
    $st.Nat = Invoke-Ros $c '/ip/firewall/nat/print' -Query '?chain=dstnat'
    $st.AllowEntries = Invoke-Ros $c '/ip/firewall/address-list/print' -Query "?list=$AllowList"
    $st.Addresses = Invoke-Ros $c '/ip/address/print'
    $st.Cloud = $null; try { $st.Cloud = Get-RosFirst $c '/ip/cloud/print' } catch { }
    $st.Services = Invoke-Ros $c '/ip/service/print'
    $st.DnsStatic = Invoke-Ros $c '/ip/dns/static/print'
    $st.Schedulers = @(Invoke-Ros $c '/system/scheduler/print' | Where-Object { $_['name'] -like 'ovpn-cutover*' })
    $st.ListMembers = Invoke-Ros $c '/interface/list/member/print'
    $st.Lists = Invoke-Ros $c '/interface/list/print'
    $st.User = Get-RosFirst $c '/user/print' -Query "?name=$($c.User)"
    $st.Group = $null
    if ($st.User) { $st.Group = Get-RosFirst $c '/user/group/print' -Query "?name=$($st.User['group'])" }

    # derived
    $st.WanIps = @($st.Addresses | Where-Object { -not (Test-RosTrue $_['disabled']) } | ForEach-Object { ($_['address'] -split '/')[0] } | Where-Object { -not (Test-PrivateIp $_) })
    if ($st.Cloud -and $st.Cloud['public-address'] -and ($st.WanIps -notcontains $st.Cloud['public-address'])) { $st.WanIps += $st.Cloud['public-address'] }
    $st.WanInterfaces = @($st.Addresses | Where-Object { -not (Test-PrivateIp (($_['address'] -split '/')[0])) } | ForEach-Object { $_['interface'] } | Select-Object -Unique)
    return $st
}

function Get-StateCert { param($State, [string]$Name) return ($State.Certificates | Where-Object { $_['name'] -eq $Name } | Select-Object -First 1) }

function Get-ServerSessions { param($State, $Server)
    # ppp active has no server reference; count ovpn sessions overall when one server, else unknown
    return @($State.Sessions).Count
}

# ---------------------------------------------------------------- firewall / zero trust
function Test-RuleAppliesToWan {
    param($State, $Rule)
    $wan = @($State.WanInterfaces)
    $ii = Get-RosVal $Rule 'in-interface'
    if ($ii) {
        if ($ii.StartsWith('!')) { return -not ($wan -contains $ii.Substring(1) -and $wan.Count -eq 1) }
        return ($wan -contains $ii)
    }
    $il = Get-RosVal $Rule 'in-interface-list'
    if ($il) {
        $neg = $il.StartsWith('!'); $name = $il.TrimStart('!')
        $list = $State.Lists | Where-Object { $_['name'] -eq $name } | Select-Object -First 1
        $members = @($State.ListMembers | Where-Object { $_['list'] -eq $name -and -not (Test-RosTrue $_['disabled']) } | ForEach-Object { $_['interface'] })
        $all = ($name -eq 'all') -or ($list -and (Get-RosVal $list 'include') -match '\ball\b')
        $hasWan = $all -or (@($wan | Where-Object { $members -contains $_ }).Count -gt 0)
        if ($neg) { return -not $hasWan }
        return $hasWan
    }
    return $true
}

function Test-RuleMatchesPort {
    param($Rule, [int]$Port, [string]$Protocol = 'tcp', $State)
    $proto = Get-RosVal $Rule 'protocol'
    if ($proto -and $proto -ne $Protocol -and $proto -ne '6') { return $false }
    $dp = Get-RosVal $Rule 'dst-port'
    if ($dp -and -not (Test-PortInSpec $dp $Port)) { return $false }
    $anyp = Get-RosVal $Rule 'port'
    if ($anyp -and -not (Test-PortInSpec $anyp $Port)) { return $false }
    $da = Get-RosVal $Rule 'dst-address'
    if ($da -and $State) {
        $neg = $da.StartsWith('!'); $cidr = $da.TrimStart('!')
        $hit = @($State.WanIps | Where-Object { Test-IpInCidr $_ $cidr }).Count -gt 0
        if ($neg) { $hit = -not $hit }
        if (-not $hit) { return $false }
    }
    $cs = Get-RosVal $Rule 'connection-state'
    if ($cs -and -not $cs.StartsWith('!') -and $cs -notmatch '\bnew\b') { return $false }
    return $true
}

# Simulates a NEW tcp packet from an unknown internet host (not in any address list) to Port.
function Test-ZeroTrustPort {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][int]$Port, [string]$Protocol = 'tcp', [string]$Group = 'Zero Trust')
    $checks = New-Object System.Collections.Generic.List[object]
    $allowList = $State.AllowList
    $allowRule = $null; $allowIdx = -1; $dropIdx = -1; $dropRule = $null
    $openRule = $null; $otherLists = @(); $jumps = @()
    $idx = 0
    foreach ($r in $State.Filter) {
        $idx++
        if ((Get-RosVal $r 'chain') -ne 'input' -or (Test-RosTrue (Get-RosVal $r 'disabled')) -or (Test-RosTrue (Get-RosVal $r 'invalid'))) { continue }
        if (-not (Test-RuleAppliesToWan $State $r)) { continue }
        if (-not (Test-RuleMatchesPort $r $Port $Protocol $State)) { continue }
        $action = Get-RosVal $r 'action' 'accept'
        $sal = Get-RosVal $r 'src-address-list'
        $sa = Get-RosVal $r 'src-address'
        $restricted = ($sa -and $sa -ne '0.0.0.0/0' -and -not $sa.StartsWith('!'))
        if ($action -eq 'accept') {
            if ($sal -eq $allowList) {
                if ($null -eq $allowRule) { $allowRule = $r; $allowIdx = $idx }
                continue
            }
            if ($sal -and -not $sal.StartsWith('!')) { $otherLists += $r; continue }
            if ($restricted) { continue }
            if ($null -eq $openRule -and $dropIdx -lt 0) { $openRule = $r }
            break
        }
        elseif ($action -in @('drop', 'reject', 'tarpit')) {
            if (($sal -and -not $sal.StartsWith('!')) -or $restricted) { continue }   # e.g. BlackList drop
            $dropIdx = $idx; $dropRule = $r
            break
        }
        elseif ($action -eq 'jump') { $jumps += $r }
    }

    $fmt = { param($r) if ($null -eq $r) { return '' } ; "правило $($r['.id'])" + $(if ($r['comment']) { " «$($r['comment'])»" } else { '' }) }

    if ($openRule) {
        $checks.Add((New-OvpnCheck $Group "Порт $Port закритий для всіх" 'FAIL' "Порт відкритий для всього інтернету: $(& $fmt $openRule) (accept без src-address-list=$allowList)" 'Обмежте правило src-address-list=MGMT_Allow або вимкніть його' -Critical))
    } elseif ($dropIdx -lt 0) {
        $checks.Add((New-OvpnCheck $Group "Порт $Port закритий для всіх" 'FAIL' 'Немає фінального drop для нових зʼєднань з WAN — input за замовчуванням accept, порт відкритий' 'Додайте в кінець input: action=drop connection-state=new in-interface=<WAN>' -Critical))
    } else {
        $checks.Add((New-OvpnCheck $Group "Порт $Port закритий для всіх" 'OK' "Невідомі адреси блокує $(& $fmt $dropRule)"))
    }
    if ($allowRule) {
        if ($dropIdx -ge 0 -and $allowIdx -gt $dropIdx) {
            $checks.Add((New-OvpnCheck $Group "Доступ через $allowList" 'FAIL' "$(& $fmt $allowRule) стоїть нижче за drop — клієнти з білого списку не підключаться" 'Перемістіть allow-правило вище за фінальний drop' -Critical))
        } else {
            $checks.Add((New-OvpnCheck $Group "Доступ через $allowList" 'OK' "$(& $fmt $allowRule), dst-port=$($allowRule['dst-port'])"))
        }
    } else {
        $checks.Add((New-OvpnCheck $Group "Доступ через $allowList" 'WARN' "Немає accept-правила з src-address-list=$allowList для порту $Port" 'Порт треба додати в dst-port allow-правила'))
    }
    foreach ($r in $otherLists) {
        $checks.Add((New-OvpnCheck $Group 'Інші списки доступу' 'WARN' "$(& $fmt $r) пропускає порт $Port зі списку '$($r['src-address-list'])' (не $allowList)" 'Перевірте, чи це очікувано'))
    }
    foreach ($r in $jumps) {
        $checks.Add((New-OvpnCheck $Group 'Jump-правила' 'WARN' "$(& $fmt $r) — jump у ланцюжок '$($r['jump-target'])', не аналізується" ''))
    }
    foreach ($n in $State.Nat) {
        if (Test-RosTrue (Get-RosVal $n 'disabled')) { continue }
        $dp = Get-RosVal $n 'dst-port'
        $pr = Get-RosVal $n 'protocol'
        if ($dp -and (Test-PortInSpec $dp $Port) -and (-not $pr -or $pr -eq $Protocol)) {
            $checks.Add((New-OvpnCheck $Group "DST-NAT порту $Port" 'FAIL' "NAT $($n['.id']) перенаправляє порт $Port → $($n['to-addresses']):$($n['to-ports'])" 'Оберіть інший порт або приберіть NAT' -Critical))
        }
    }
    return [pscustomobject]@{ Checks = $checks.ToArray(); AllowRule = $allowRule; DropRule = $dropRule; OpenRule = $openRule }
}

# ---------------------------------------------------------------- port helpers
function Get-UsedPorts {
    param($State)
    $used = @{}
    foreach ($s in $State.Services) { if (-not (Test-RosTrue $s['disabled'])) { $used[[int]$s['port']] = "сервіс $($s['name'])" } }
    foreach ($s in $State.Servers) { $used[[int]$s['port']] = "OpenVPN $($s['name'])" }
    foreach ($n in $State.Nat) {
        $dp = Get-RosVal $n 'dst-port'
        foreach ($p in ($dp -split ',')) { if ($p -match '^\d+$') { $used[[int]$p] = "DST-NAT $($n['.id'])" } }
    }
    foreach ($r in $State.Filter) {
        if ((Get-RosVal $r 'chain') -ne 'input') { continue }
        foreach ($p in ((Get-RosVal $r 'dst-port') -split ',')) { if ($p -match '^\d+$' -and -not $used.ContainsKey([int]$p)) { $used[[int]$p] = "firewall $($r['.id'])" } }
    }
    return $used
}

function Test-OvpnPortFree {
    param($State, [int]$Port)
    if ($Port -lt 1024 -or $Port -gt 65535) { return "Порт має бути в діапазоні 1024–65535" }
    $used = Get-UsedPorts $State
    if ($used.ContainsKey($Port)) { return "Порт $Port вже використовується: $($used[$Port])" }
    return $null
}

function Get-OvpnSuggestedPort {
    param($State, [int]$Min = 20000, [int]$Max = 60999)
    $rnd = New-Object System.Random
    for ($i = 0; $i -lt 500; $i++) {
        $p = $rnd.Next($Min, $Max + 1)
        if (-not (Test-OvpnPortFree $State $p)) {
            $zt = Test-ZeroTrustPort -State $State -Port $p
            if (-not ($zt.Checks | Where-Object { $_.Status -eq 'FAIL' })) { return $p }
        }
    }
    throw 'Не вдалося підібрати вільний порт'
}

# ---------------------------------------------------------------- DNS
function Resolve-OvpnHostPublic {
    param([string]$HostName)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$ip)) { return @($HostName) }
    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            return @(Resolve-DnsName -Name $HostName -Type A -Server 8.8.8.8 -DnsOnly -QuickTimeout -ErrorAction Stop |
                    Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
        } catch { }
    }
    try { return @([System.Net.Dns]::GetHostAddresses($HostName) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() }) }
    catch { return @() }
}

function Test-OvpnHost {
    param($State, [string]$HostName, [string]$Label = 'VPN-хост')
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $HostName) { return $out.ToArray() }
    if ($HostName -notmatch '^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$') {
        $out.Add((New-OvpnCheck 'Профіль' "$Label $HostName" 'FAIL' 'Некоректне імʼя хоста' '' -Critical)); return $out.ToArray()
    }
    $ips = @(Resolve-OvpnHostPublic $HostName)
    if ($ips.Count -eq 0) {
        $out.Add((New-OvpnCheck 'Профіль' "$Label $HostName" 'FAIL' 'Не резолвиться через публічний DNS (8.8.8.8)' 'Перевірте A-запис' -Critical))
    } elseif (@($ips | Where-Object { $State.WanIps -contains $_ }).Count -gt 0) {
        $out.Add((New-OvpnCheck 'Профіль' "$Label $HostName" 'OK' "Публічний DNS: $($ips -join ', ') = WAN роутера"))
    } else {
        $out.Add((New-OvpnCheck 'Профіль' "$Label $HostName" 'WARN' "Публічний DNS: $($ips -join ', '), WAN роутера: $($State.WanIps -join ', ')" 'Можливий NAT/інший маршрутизатор або хост ще не переїхав'))
    }
    $static = $State.DnsStatic | Where-Object { $_['name'] -eq $HostName -and -not (Test-RosTrue $_['disabled']) } | Select-Object -First 1
    if ($static) {
        $out.Add((New-OvpnCheck 'Профіль' "$Label у локальному DNS" 'INFO' "Static DNS на роутері: $HostName → $($static['address']) (з офісної мережі профіль іде на цю адресу)"))
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------- certificates
function Get-CertCheck {
    param($Cert, [string]$Role, [int]$WarnDays)
    $out = New-Object System.Collections.Generic.List[object]
    $name = $Cert['name']
    $exp = ConvertFrom-RosDate $Cert['invalid-after']
    $days = if ($exp) { [int]($exp - (Get-Date)).TotalDays } else { -1 }
    if (Test-RosTrue $Cert['revoked']) { $out.Add((New-OvpnCheck 'Сертифікати' "$Role $name" 'FAIL' 'Відкликаний' '' -Critical)) }
    elseif ($days -lt 0) { $out.Add((New-OvpnCheck 'Сертифікати' "$Role $name" 'FAIL' "Прострочений ($($Cert['invalid-after']))" '' -Critical)) }
    elseif ($days -lt $WarnDays) { $out.Add((New-OvpnCheck 'Сертифікати' "$Role $name" 'WARN' "Діє до $($Cert['invalid-after']) (залишилось $days дн.)" 'Плануйте перевипуск')) }
    else { $out.Add((New-OvpnCheck 'Сертифікати' "$Role $name" 'OK' "Діє до $($Cert['invalid-after']) ($days дн.)")) }

    $ks = $Cert['key-size']; $kt = $Cert['key-type']
    if ($ks -match '^\d+$') {
        $k = [int]$ks
        if ($k -lt 2048) { $out.Add((New-OvpnCheck 'Сертифікати' "$Role ключ" 'FAIL' "RSA $k — небезпечно" 'Перевипустіть з ключем ≥ 4096' -Critical)) }
        elseif ($k -lt 3072) { $out.Add((New-OvpnCheck 'Сертифікати' "$Role ключ" 'WARN' "RSA $k — застаріло" 'Рекомендовано ≥ 4096')) }
        else { $out.Add((New-OvpnCheck 'Сертифікати' "$Role ключ" 'OK' "$($kt.ToUpper()) $k")) }
    } elseif ($ks) { $out.Add((New-OvpnCheck 'Сертифікати' "$Role ключ" 'OK' "EC $ks")) }

    $dg = $Cert['digest-algorithm']
    if ($dg -match 'md5|sha1$') { $out.Add((New-OvpnCheck 'Сертифікати' "$Role підпис" 'FAIL' "Алгоритм підпису $dg застарів" 'Перевипустіть з sha256+' -Critical)) }
    return $out.ToArray()
}

# ---------------------------------------------------------------- permissions
$script:RequiredPolicies = [ordered]@{
    api       = 'доступ через API'
    read      = 'читання конфігурації'
    write     = 'створення сертифікатів, серверів, правил'
    test      = 'ping/monitor (RADIUS monitor)'
    ftp       = 'читання файлів (/file/read): скачування сертифікатів і backup'
    sensitive = 'експорт приватного ключа сертифіката'
}

function Get-OvpnPermissionReport {
    param([Parameter(Mandatory)]$State)
    $pol = Get-RosVal $State.Group 'policy'
    $have = @(($pol -split ',') | Where-Object { $_ -and -not $_.StartsWith('!') })
    $missing = @($script:RequiredPolicies.Keys | Where-Object { $have -notcontains $_ })
    $grp = Get-RosVal $State.User 'group'
    $all = ($script:RequiredPolicies.Keys -join ',')
    $fix = @(
        "/user group add name=ovpn-admin policy=$all",
        "/user set $($State.ApiUser) group=ovpn-admin"
    )
    if ($grp -and $grp -notin @('full', 'read', 'write')) {
        $fix += "# або додати політики до наявної групи '$grp':"
        $fix += "/user group set $grp policy=$((@($have) + $missing | Select-Object -Unique) -join ',')"
    }
    return [pscustomobject]@{
        User = $State.ApiUser; Group = $grp; Have = $have; Missing = $missing
        Details = @($missing | ForEach-Object { "$_ — $($script:RequiredPolicies[$_])" })
        Fix = $fix; Ok = ($missing.Count -eq 0)
    }
}

# ---------------------------------------------------------------- main diagnostics
function Test-RouterState {
    param([Parameter(Mandatory)]$State, [string]$VpnHost, [string]$VpnHost2)
    $C = New-Object System.Collections.Generic.List[object]
    $add = { param($x) foreach ($i in @($x)) { if ($i) { $C.Add($i) } } }

    # --- system
    $ver = Get-RosVersion (Get-RosVal $State.Resource 'version')
    $board = Get-RosVal $State.Resource 'board-name'
    if ($ver.Major -ge 7 -and ($ver -ge [version]'7.17')) { & $add (New-OvpnCheck 'Система' 'RouterOS' 'OK' "$($State.Identity): $board, RouterOS $(Get-RosVal $State.Resource 'version')") }
    elseif ($ver.Major -ge 7) { & $add (New-OvpnCheck 'Система' 'RouterOS' 'WARN' "RouterOS $(Get-RosVal $State.Resource 'version') — кілька OVPN-серверів підтримуються з 7.17" 'Оновіть RouterOS') }
    else { & $add (New-OvpnCheck 'Система' 'RouterOS' 'FAIL' "RouterOS $(Get-RosVal $State.Resource 'version') — потрібна 7.17+ (паралельні сервери, /file/read)" 'Оновіть RouterOS' -Critical) }

    if ($State.Ntp) {
        if ((Get-RosVal $State.Ntp 'status') -eq 'synchronized') { & $add (New-OvpnCheck 'Система' 'NTP' 'OK' "Синхронізовано з $(Get-RosVal $State.Ntp 'synced-server')") }
        else { & $add (New-OvpnCheck 'Система' 'NTP' 'WARN' "Статус: $(Get-RosVal $State.Ntp 'status' 'вимкнено')" 'Дати сертифікатів беруться з годинника роутера') }
    }
    try {
        $d = ConvertFrom-RosDate ("{0} {1}" -f $State.Clock['date'], $State.Clock['time'])
        $off = Get-RosVal $State.Clock 'gmt-offset' '+00:00'
        if ($d -and $off -match '^([+-])(\d{2}):(\d{2})') {
            $ts = New-Object TimeSpan ([int]$Matches[2]), ([int]$Matches[3]), 0
            if ($Matches[1] -eq '-') { $ts = $ts.Negate() }
            $rt = New-Object DateTimeOffset $d, $ts
            $age = ((Get-Date) - $State.CollectedAt).TotalSeconds
            $diff = [math]::Abs(([DateTimeOffset]::Now.AddSeconds(-$age) - $rt).TotalSeconds)
            if ($diff -lt 120) { & $add (New-OvpnCheck 'Система' 'Годинник' 'OK' "Розбіжність з ПК: $([int]$diff) с") }
            else { & $add (New-OvpnCheck 'Система' 'Годинник' 'WARN' "Розбіжність з ПК: $([int]$diff) с" 'Перевірте час на роутері / ПК') }
        }
    } catch { }

    # --- API permissions
    $perm = Get-OvpnPermissionReport $State
    if ($perm.Ok) { & $add (New-OvpnCheck 'Права API' "Група '$($perm.Group)'" 'OK' ($perm.Have -join ',')) }
    else {
        & $add (New-OvpnCheck 'Права API' "Група '$($perm.Group)'" 'FAIL' ("Бракує: " + ($perm.Details -join '; ')) (($perm.Fix | Where-Object { $_ -notlike '#*' } | Select-Object -First 2) -join ' ; ') -Critical)
    }

    # --- OpenVPN servers
    if (@($State.Servers).Count -eq 0) { & $add (New-OvpnCheck 'OpenVPN' 'Сервери' 'FAIL' 'OpenVPN-сервер ще не налаштовано' 'Вкладка «CA і сервер» → первинне налаштування' -Critical) }
    $caNames = @()
    foreach ($s in $State.Servers) {
        $n = $s['name']; $g = "OpenVPN $n"
        $en = -not (Test-RosTrue $s['disabled'])
        $sess = @($State.Sessions).Count
        & $add (New-OvpnCheck $g 'Стан' $(if ($en) { 'OK' } else { 'INFO' }) ("{0}, {1}/{2}, mode={3}, профіль {4}; активних OVPN-сесій на роутері: {5}" -f $(if ($en) { 'увімкнено' } else { 'вимкнено' }), $s['protocol'], $s['port'], $s['mode'], $s['default-profile'], $sess))
        if (Test-RosTrue $s['require-client-certificate']) { & $add (New-OvpnCheck $g 'Клієнтський сертифікат' 'OK' 'require-client-certificate=yes') }
        else { & $add (New-OvpnCheck $g 'Клієнтський сертифікат' 'FAIL' 'require-client-certificate=no — сертифікат клієнта не перевіряється' 'set require-client-certificate=yes' -Critical) }
        $tv = $s['tls-version']
        if ($tv -eq 'only-1.2' -or $tv -eq 'only-1.3') { & $add (New-OvpnCheck $g 'TLS' 'OK' $tv) } else { & $add (New-OvpnCheck $g 'TLS' 'WARN' "tls-version=$tv" 'Рекомендовано only-1.2') }
        $ci = $s['cipher']
        if ($ci -match 'gcm') { & $add (New-OvpnCheck $g 'Шифр' 'OK' $ci) } else { & $add (New-OvpnCheck $g 'Шифр' 'WARN' "cipher=$ci (без GCM)" 'Рекомендовано aes256-gcm') }
        if ($s['auth'] -match 'md5|sha1$|null') { & $add (New-OvpnCheck $g 'Auth' 'WARN' "auth=$($s['auth'])" 'Рекомендовано sha256+') }
        $um = $s['user-auth-method']
        & $add (New-OvpnCheck $g 'Авторизація користувача' 'INFO' "user-auth-method=$um (всередині TLS-тунелю)")
        $prof = $State.Profiles | Where-Object { $_['name'] -eq $s['default-profile'] } | Select-Object -First 1
        if (-not $prof) { & $add (New-OvpnCheck $g 'PPP-профіль' 'FAIL' "Профіль '$($s['default-profile'])' не знайдено" '' -Critical) }
        $sc = Get-StateCert $State $s['certificate']
        if (-not $sc) { & $add (New-OvpnCheck $g 'Серверний сертифікат' 'FAIL' "Сертифікат '$($s['certificate'])' не знайдено" '' -Critical) }
        else {
            & $add (Get-CertCheck $sc 'Сервер' 365)
            if ($sc['key-usage'] -notmatch 'tls-server') { & $add (New-OvpnCheck 'Сертифікати' "Сервер $($sc['name']) key-usage" 'WARN' "key-usage=$($sc['key-usage']) без tls-server — remote-cert-tls server не пройде" 'Перевипустіть серверний сертифікат з tls-server') }
            if ($sc['ca']) { $caNames += $sc['ca'] }
        }
    }

    # --- CA
    foreach ($caName in ($caNames | Select-Object -Unique)) {
        $ca = Get-StateCert $State $caName
        if (-not $ca) { & $add (New-OvpnCheck 'Сертифікати' "CA $caName" 'FAIL' 'CA не знайдено на роутері' '' -Critical); continue }
        & $add (Get-CertCheck $ca 'CA' 730)
        if (Test-RosTrue $ca['trusted']) { & $add (New-OvpnCheck 'Сертифікати' "CA $caName trusted" 'OK' 'trusted=yes') }
        else { & $add (New-OvpnCheck 'Сертифікати' "CA $caName trusted" 'WARN' 'trusted=no — RouterOS може не довіряти ланцюжку клієнтів' 'Вкладка «CA і сервер» → «Позначити trusted»') }
        if ($ca['key-usage'] -notmatch 'key-cert-sign') { & $add (New-OvpnCheck 'Сертифікати' "CA $caName key-usage" 'FAIL' "key-usage=$($ca['key-usage']) без key-cert-sign" '' -Critical) }
        if (Test-RosTrue $ca['private-key']) { & $add (New-OvpnCheck 'Сертифікати' "CA $caName приватний ключ" 'OK' 'Є — роутер може підписувати клієнтські сертифікати') }
        else { & $add (New-OvpnCheck 'Сертифікати' "CA $caName приватний ключ" 'FAIL' 'Немає приватного ключа CA — підпис неможливий' '' -Critical) }
    }

    # --- client certificates
    $clients = @($State.Certificates | Where-Object { $_['key-usage'] -match 'tls-client' -and $_['ca'] })
    foreach ($cc in $clients) {
        $exp = ConvertFrom-RosDate $cc['invalid-after']
        $cstate = if (Test-RosTrue $cc['revoked']) { 'відкликаний' } elseif (Test-RosTrue $cc['expired']) { 'прострочений' } else { 'діє' }
        $cst = if ($cstate -eq 'діє') { 'INFO' } elseif ($cstate -eq 'прострочений') { 'WARN' } else { 'INFO' }
        $fix = if ($cstate -eq 'прострочений') { 'Можна відкликати/видалити на вкладці «Обслуговування»' } else { '' }
        if ($cstate -eq 'діє' -and $exp -and ($exp - (Get-Date)).TotalDays -lt 45) {
            $cst = 'WARN'; $cstate = "діє ще $([int]($exp - (Get-Date)).TotalDays) дн."; $fix = 'Час випускати сертифікат наступного року'
        }
        & $add (New-OvpnCheck 'Клієнтські сертифікати' "$($cc['name']) (CN=$($cc['common-name']))" $cst "$cstate, до $($cc['invalid-after']), $($cc['key-type']) $($cc['key-size'])" $fix)
    }

    # --- PPP profile & pool
    foreach ($pn in (@($State.Servers | ForEach-Object { $_['default-profile'] }) | Select-Object -Unique)) {
        $p = $State.Profiles | Where-Object { $_['name'] -eq $pn } | Select-Object -First 1
        if (-not $p) { continue }
        $ra = Get-RosVal $p 'remote-address'
        $pool = $State.Pools | Where-Object { $_['name'] -eq $ra } | Select-Object -First 1
        if ($pool) {
            $tot = [int](Get-RosVal $pool 'total' 0); $used = [int](Get-RosVal $pool 'used' 0)
            $free = $tot - $used
            $stt = if ($tot -gt 0 -and $free -lt [math]::Max(5, $tot * 0.1)) { 'WARN' } else { 'OK' }
            & $add (New-OvpnCheck 'PPP' "Пул $ra" $stt "$($pool['ranges']): зайнято $used з $tot")
        } elseif ($ra) { & $add (New-OvpnCheck 'PPP' "Профіль $pn" 'INFO' "remote-address=$ra (не пул або адресу видає RADIUS)") }
        & $add (New-OvpnCheck 'PPP' "Профіль $pn" 'INFO' ("only-one={0}, use-encryption={1}, on-up/on-down: {2}" -f $p['only-one'], $p['use-encryption'], $(if ($p['on-up'] -or $p['on-down']) { 'є скрипти' } else { 'немає' })))
    }

    # --- AAA / RADIUS
    $useRadius = Test-RosTrue (Get-RosVal $State.Aaa 'use-radius')
    if ($useRadius) { & $add (New-OvpnCheck 'RADIUS' 'PPP AAA' 'OK' ("use-radius=yes, accounting={0}, interim-update={1}" -f $State.Aaa['accounting'], $State.Aaa['interim-update'])) }
    else { & $add (New-OvpnCheck 'RADIUS' 'PPP AAA' 'WARN' 'use-radius=no — користувачі тільки з /ppp secret' '') }
    $pppRadius = @($State.Radius | Where-Object { $_['service'] -match '\bppp\b' -and -not (Test-RosTrue $_['disabled']) })
    if ($useRadius -and $pppRadius.Count -eq 0) { & $add (New-OvpnCheck 'RADIUS' 'Сервери' 'FAIL' 'use-radius=yes, але немає активного RADIUS з service=ppp' '' -Critical) }
    foreach ($r in $pppRadius) {
        $m = $State.RadiusMonitor[$r['.id']]
        $det = "$($r['address']) auth:$($r['authentication-port']) acct:$($r['accounting-port']) timeout=$($r['timeout'])"
        $stt = 'OK'
        if ($m) {
            $req = [long](Get-RosVal $m 'requests' 0); $acc = [long](Get-RosVal $m 'accepts' 0); $rej = [long](Get-RosVal $m 'rejects' 0); $to = [long](Get-RosVal $m 'timeouts' 0)
            $det += "; запитів $req, accept $acc, reject $rej, timeout $to, rtt $(Get-RosVal $m 'last-request-rtt' '-')"
            if ($req -gt 0 -and $acc -eq 0) { $stt = 'FAIL' }
            elseif ($req -gt 20 -and ($to / [double]$req) -gt 0.05) { $stt = 'WARN' }
        }
        $fix = if ($stt -eq 'FAIL') { 'RADIUS не приймає жодного запиту — перевірте secret/NPS' } elseif ($stt -eq 'WARN') { 'Багато таймаутів RADIUS' } else { '' }
        & $add (New-OvpnCheck 'RADIUS' "Сервер $($r['address'])" $stt $det $fix -Critical:($stt -eq 'FAIL'))
        if ($r['comment'] -and $r['comment'].Length -ge 20 -and $r['comment'] -notmatch '\s') {
            & $add (New-OvpnCheck 'RADIUS' "Коментар запису $($r['address'])" 'WARN' 'Коментар схожий на відкритий секрет/пароль' 'Приберіть секрет з коментаря')
        }
    }

    # --- Zero Trust per enabled server
    foreach ($s in $State.Servers) {
        if (Test-RosTrue $s['disabled']) { continue }
        $zt = Test-ZeroTrustPort -State $State -Port ([int]$s['port']) -Protocol $s['protocol'] -Group "Zero Trust ($($s['name']):$($s['port']))"
        & $add $zt.Checks
    }
    $localOvpn = @($State.Secrets | Where-Object { $_['service'] -in @('ovpn', 'any') -and -not (Test-RosTrue $_['disabled']) })
    & $add (New-OvpnCheck 'PPP' 'Локальні користувачі (/ppp secret)' 'INFO' "ovpn/any: $($localOvpn.Count)$(if ($localOvpn.Count) { ' — ' + (($localOvpn | Select-Object -First 8 | ForEach-Object { $_['name'] }) -join ', ') })")
    $vpnEntries = @($State.AllowEntries | Where-Object { $_['comment'] -like 'VPN_*' -and -not (Test-RosTrue $_['disabled']) })
    & $add (New-OvpnCheck 'Zero Trust' "Список $($State.AllowList)" 'INFO' "Записів: $(@($State.AllowEntries).Count), з них від порталу (VPN_*): $($vpnEntries.Count)")

    # --- host
    & $add (Test-OvpnHost $State $VpnHost 'VPN-хост')
    if ($VpnHost2) { & $add (Test-OvpnHost $State $VpnHost2 'Резервний хост') }

    # --- pending cutovers
    foreach ($sc in $State.Schedulers) {
        & $add (New-OvpnCheck 'Перехід' "Scheduler $($sc['name'])" 'INFO' "Запуск $($sc['start-date']) $($sc['start-time']), $(if (Test-RosTrue $sc['disabled']) { 'вимкнено' } else { 'активний' })")
    }
    return $C.ToArray()
}

Export-ModuleMember -Function Get-OvpnPermissionReport, New-OvpnCheck, Get-RosVal, Test-RosTrue, ConvertFrom-RosDate, Get-RosVersion, Test-PortInSpec, Test-IpInCidr, Test-PrivateIp,
    Get-RouterState, Get-StateCert, Test-ZeroTrustPort, Get-UsedPorts, Test-OvpnPortFree, Get-OvpnSuggestedPort, Resolve-OvpnHostPublic, Test-OvpnHost, Test-RouterState
