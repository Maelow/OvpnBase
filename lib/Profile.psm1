# .ovpn profile generation and parsing.

function ConvertTo-OvpnRoute {
    param([string]$Line)
    $l = $Line.Trim()
    if (-not $l -or $l.StartsWith('#')) { return $null }
    $l = $l -replace '^route\s+', ''
    if ($l -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $bits = [int]$Matches[2]
        if ($bits -gt 32) { throw "Некоректний маршрут: $Line" }
        $mask = if ($bits -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl (32 - $bits)) }
        $m = '{0}.{1}.{2}.{3}' -f (($mask -shr 24) -band 255), (($mask -shr 16) -band 255), (($mask -shr 8) -band 255), ($mask -band 255)
        return "$($Matches[1]) $m"
    }
    if ($l -match '^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$') { return "$($Matches[1]) $($Matches[2])" }
    throw "Некоректний маршрут: '$Line' (очікується 192.168.1.0/24 або 192.168.1.0 255.255.255.0)"
}

function ConvertTo-CidrRoute {
    param([string]$Route)
    $p = $Route.Split(' ')
    if ($p.Count -ne 2) { return $Route }
    $bits = 0
    foreach ($o in $p[1].Split('.')) { $v = [int]$o; while ($v -gt 0) { $bits += ($v -band 1); $v = $v -shr 1 } }
    return "$($p[0])/$bits"
}

# Parses an existing profile (used for defaults on first run).
function Read-OvpnProfileInfo {
    param([string]$Path)
    $t = Get-Content -LiteralPath $Path -Raw
    $info = [ordered]@{ Hosts = @(); Port = $null; Proto = 'tcp'; Routes = @(); FriendlyName = $null; CertCn = $null }
    foreach ($line in ($t -split "`r?`n")) {
        if ($line -match '^\s*remote\s+(\S+)(?:\s+(\d+))?') { $info.Hosts += $Matches[1]; if ($Matches[2]) { $info.Port = [int]$Matches[2] } }
        elseif ($line -match '^\s*port\s+(\d+)') { $info.Port = [int]$Matches[1] }
        elseif ($line -match '^\s*proto\s+(\S+)') { $info.Proto = $Matches[1] }
        elseif ($line -match '^\s*route\s+(\S+\s+\S+)') { $info.Routes += (ConvertTo-CidrRoute $Matches[1]) }
        elseif ($line -match '^\s*setenv\s+FRIENDLY_NAME\s+"?([^"]+)"?') { $info.FriendlyName = $Matches[1] }
    }
    return $info
}

function New-OvpnProfileText {
    param(
        [ValidateSet('Windows', 'macOS')][string]$Platform,
        [Parameter(Mandatory)][string[]]$Hosts,
        [Parameter(Mandatory)][int]$Port,
        [string]$Protocol = 'tcp',
        [Parameter(Mandatory)][string]$CaPem,
        [Parameter(Mandatory)][string]$CertPem,
        [Parameter(Mandatory)][string]$KeyPem,
        [string]$FriendlyName,
        [string[]]$Routes,
        [string]$ServerCn,
        [bool]$Modern = $true
    )
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('client')
    $L.Add('dev tun')
    $L.Add("proto $Protocol")
    foreach ($h in $Hosts) { if ($h) { $L.Add("remote $h $Port") } }
    if (@($Hosts | Where-Object { $_ }).Count -gt 1) { $L.Add('# хости пробуються по черзі (remote-random вимкнено)') }
    $L.Add('resolv-retry infinite')
    $L.Add('nobind')
    $L.Add('persist-key')
    $L.Add('persist-tun')
    if ($Modern) {
        $L.Add('remote-cert-tls server')
        if ($ServerCn) { $L.Add("verify-x509-name $ServerCn name") }
        $L.Add('tls-version-min 1.2')
        $L.Add('data-ciphers AES-256-GCM')
        $L.Add('auth-user-pass')
        $L.Add('auth-nocache')
    } else {
        $L.Add('ns-cert-type server')
        $L.Add('cipher AES-256-GCM')
        $L.Add('auth-user-pass')
    }
    if ($FriendlyName) { $L.Add("setenv FRIENDLY_NAME `"$FriendlyName`"") }
    $L.Add('route-nopull')
    foreach ($r in $Routes) { $rr = ConvertTo-OvpnRoute $r; if ($rr) { $L.Add("route $rr") } }
    if ($Platform -eq 'Windows') {
        $L.Add('route-method exe')
        $L.Add('ip-win32 netsh')
    }
    $L.Add('verb 3')
    $L.Add('<ca>'); $L.Add((Get-PemBlock $CaPem 'CERTIFICATE').Trim()); $L.Add('</ca>')
    $L.Add('<cert>'); $L.Add((Get-PemBlock $CertPem 'CERTIFICATE').Trim()); $L.Add('</cert>')
    $keyBlock = $null
    foreach ($lbl in @('ENCRYPTED PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'PRIVATE KEY')) {
        $keyBlock = Get-PemBlock $KeyPem $lbl
        if ($keyBlock) { break }
    }
    if (-not $keyBlock) { throw 'Не знайдено приватний ключ у PEM' }
    $L.Add('<key>'); $L.Add($keyBlock.Trim()); $L.Add('</key>')

    $nl = if ($Platform -eq 'Windows') { "`r`n" } else { "`n" }
    return (($L | ForEach-Object { $_ -replace "`r?`n", $nl }) -join $nl) + $nl
}

function New-OvpnReadme {
    param([ValidateSet('Windows', 'macOS')][string]$Platform, [string]$ProfileName, [int]$Year, [string]$PortalUrl, [string]$ValidTo)
    $portal = if ($PortalUrl) { "відкрийте портал $PortalUrl і авторизуйтесь" } else { 'авторизуйтесь на корпоративному порталі доступу (Zero Trust)' }
    $common = @"
VPN $Year — інструкція

Профіль: $ProfileName
Сертифікат діє до: $ValidTo

ВАЖЛИВО: перед кожним підключенням $portal —
без цього VPN-порт для вашої IP-адреси закритий.

Під час підключення потрібні:
  1) логін і пароль VPN (ваш обліковий запис);
  2) пароль (паскей) приватного ключа — повідомляється окремо.

"@
    if ($Platform -eq 'Windows') {
        $steps = @"
Windows:
  1. Встановіть OpenVPN Connect або OpenVPN GUI (https://openvpn.net/client/).
  2. Імпортуйте файл $ProfileName (File → Import / «Import profile»).
  3. Видаліть профіль попереднього року.
  4. Підключіться, введіть логін/пароль і паскей ключа.
"@
    } else {
        $steps = @"
macOS:
  1. Встановіть OpenVPN Connect (https://openvpn.net/client/) або Tunnelblick.
  2. Перетягніть $ProfileName у вікно OpenVPN Connect (або двічі клацніть для Tunnelblick).
  3. Видаліть профіль попереднього року.
  4. Підключіться, введіть логін/пароль і паскей ключа.
"@
    }
    return ($common + $steps)
}

Export-ModuleMember -Function ConvertTo-OvpnRoute, ConvertTo-CidrRoute, Read-OvpnProfileInfo, New-OvpnProfileText, New-OvpnReadme
