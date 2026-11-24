# RouterOS binary API client (port 8728) + logging helpers.
# Compatible with Windows PowerShell 5.1 and PowerShell 7+.

$script:Enc = $null
$script:SensitiveKeys = @('password', 'export-passphrase', 'passphrase', 'secret')

function Get-RosEncoding {
    if ($null -eq $script:Enc) {
        try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance) } catch { }
        try { $script:Enc = [System.Text.Encoding]::GetEncoding(1251) }
        catch { $script:Enc = [System.Text.Encoding]::GetEncoding(28591) }
    }
    return $script:Enc
}

# ---------------------------------------------------------------- logging
function Write-OvpnLog {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'CMD', 'STEP')][string]$Level = 'INFO'
    )
    $line = '{0:HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    $sync = Get-Variable -Name OvpnSync -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($sync -and $sync.ContainsKey('Log')) { $sync.Log.Enqueue($line) }
    else {
        $color = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'CMD' { 'Cyan' } 'STEP' { 'Magenta' } default { 'Gray' } }
        Write-Host $line -ForegroundColor $color
    }
}

# Reports workflow step state to the GUI (no-op in console mode).
function Set-OvpnStep {
    param([Parameter(Mandatory)][string]$Key,
          [ValidateSet('wait', 'run', 'ok', 'warn', 'fail', 'skip')][string]$Status,
          [string]$Detail = '')
    $sync = Get-Variable -Name OvpnSync -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($sync -and $sync.ContainsKey('Steps')) {
        $sync.Steps.Enqueue([pscustomobject]@{ Key = $Key; Status = $Status; Detail = $Detail })
    }
    $lvl = switch ($Status) { 'ok' { 'OK' } 'warn' { 'WARN' } 'fail' { 'ERROR' } default { 'STEP' } }
    if ($Status -ne 'wait') { Write-OvpnLog -Level $lvl -Message ("[{0}] {1} {2}" -f $Key, $Status, $Detail) }
}

# ---------------------------------------------------------------- wire format
function ConvertTo-RosLength {
    param([int]$Length)
    [long]$n = $Length
    if ($n -lt 0x80) { return , [byte[]]@($n) }
    if ($n -lt 0x4000) { $n = $n -bor 0x8000; return , [byte[]]@((($n -shr 8) -band 0xFF), ($n -band 0xFF)) }
    if ($n -lt 0x200000) { $n = $n -bor 0xC00000; return , [byte[]]@((($n -shr 16) -band 0xFF), (($n -shr 8) -band 0xFF), ($n -band 0xFF)) }
    if ($n -lt 0x10000000) {
        $n = $n -bor 0xE0000000L
        return , [byte[]]@((($n -shr 24) -band 0xFF), (($n -shr 16) -band 0xFF), (($n -shr 8) -band 0xFF), ($n -band 0xFF))
    }
    return , [byte[]]@(0xF0, (($n -shr 24) -band 0xFF), (($n -shr 16) -band 0xFF), (($n -shr 8) -band 0xFF), ($n -band 0xFF))
}

function Read-RosBytes {
    param($Connection, [int]$Count)
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        $r = $Connection.Stream.Read($buf, $off, $Count - $off)
        if ($r -le 0) { throw "З'єднання з RouterOS закрито віддаленою стороною" }
        $off += $r
    }
    return , $buf
}

function Read-RosLength {
    param($Connection)
    [int]$b = (Read-RosBytes $Connection 1)[0]
    if ($b -lt 0x80) { return $b }
    if ($b -lt 0xC0) { $x = Read-RosBytes $Connection 1; return ((($b -band 0x3F) -shl 8) -bor [int]$x[0]) }
    if ($b -lt 0xE0) { $x = Read-RosBytes $Connection 2; return ((($b -band 0x1F) -shl 16) -bor ([int]$x[0] -shl 8) -bor [int]$x[1]) }
    if ($b -lt 0xF0) { $x = Read-RosBytes $Connection 3; return ((($b -band 0x0F) -shl 24) -bor ([int]$x[0] -shl 16) -bor ([int]$x[1] -shl 8) -bor [int]$x[2]) }
    $x = Read-RosBytes $Connection 4
    return (([int]$x[0] -shl 24) -bor ([int]$x[1] -shl 16) -bor ([int]$x[2] -shl 8) -bor [int]$x[3])
}

function Read-RosSentence {
    param($Connection)
    $enc = Get-RosEncoding
    $words = New-Object System.Collections.Generic.List[string]
    while ($true) {
        $len = Read-RosLength $Connection
        if ($len -eq 0) { break }
        $bytes = Read-RosBytes $Connection $len
        $words.Add($enc.GetString($bytes))
    }
    return , $words
}

function Format-RosWordsForLog {
    param([string[]]$Words)
    $out = foreach ($w in $Words) {
        if ($w -match '^=([^=]+)=') {
            if ($script:SensitiveKeys -contains $Matches[1]) { "=$($Matches[1])=***" } else { $w }
        } else { $w }
    }
    return ($out -join ' ')
}

# Low level: send words, collect reply. Returns @{ Rows = [hashtable[]]; Done = [hashtable] }.
function Invoke-RosRaw {
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][string[]]$Words,
        [int]$TimeoutMs = 0
    )
    $enc = Get-RosEncoding
    $buf = New-Object System.Collections.Generic.List[byte]
    foreach ($w in $Words) {
        $b = $enc.GetBytes($w)
        $buf.AddRange([byte[]](ConvertTo-RosLength $b.Length))
        $buf.AddRange($b)
    }
    $buf.Add(0)
    $arr = $buf.ToArray()

    $oldTimeout = $Connection.Stream.ReadTimeout
    if ($TimeoutMs -gt 0) { $Connection.Stream.ReadTimeout = $TimeoutMs }
    try {
        $Connection.Stream.Write($arr, 0, $arr.Length)
        $Connection.Stream.Flush()

        $rows = New-Object System.Collections.Generic.List[object]
        $done = @{}
        $trap = $null
        while ($true) {
            $s = Read-RosSentence $Connection
            if ($s.Count -eq 0) { continue }
            $type = $s[0]
            $attrs = [ordered]@{}
            for ($i = 1; $i -lt $s.Count; $i++) {
                $w = $s[$i]
                if ($w.StartsWith('=')) {
                    $p = $w.IndexOf('=', 1)
                    if ($p -lt 0) { $attrs[$w.Substring(1)] = '' }
                    else { $attrs[$w.Substring(1, $p - 1)] = $w.Substring($p + 1) }
                }
            }
            if ($type -eq '!re') { $rows.Add($attrs) }
            elseif ($type -eq '!trap') { if ($null -eq $trap) { $trap = $attrs } }
            elseif ($type -eq '!fatal') {
                $msg = if ($s.Count -gt 1) { $s[1] } else { 'fatal' }
                throw "RouterOS !fatal: $msg"
            }
            elseif ($type -eq '!done') { $done = $attrs; break }
            # '!empty' (RouterOS 7.18+) -> no rows, keep reading until !done
        }
        if ($null -ne $trap) {
            $m = $trap['message']
            if (-not $m) { $m = ($trap.Values -join '; ') }
            throw "RouterOS: $m  [$(Format-RosWordsForLog $Words)]"
        }
        return @{ Rows = $rows.ToArray(); Done = $done }
    }
    finally {
        $Connection.Stream.ReadTimeout = $oldTimeout
    }
}

function Connect-RouterOs {
    param(
        [Parameter(Mandatory)][string]$Address,
        [int]$Port = 8728,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Password,
        [int]$TimeoutMs = 15000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($Address, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
        $client.Close()
        throw "Таймаут підключення до ${Address}:$Port"
    }
    try { $client.EndConnect($iar) }
    catch { $client.Close(); throw "Не вдалося підключитись до ${Address}:${Port}: $($_.Exception.InnerException.Message)$($_.Exception.Message)" }

    $stream = $client.GetStream()
    $stream.ReadTimeout = $TimeoutMs
    $stream.WriteTimeout = $TimeoutMs
    $conn = [pscustomobject]@{
        Client = $client; Stream = $stream; Address = $Address; Port = $Port; User = $User; TimeoutMs = $TimeoutMs
    }
    try { [void](Invoke-RosRaw -Connection $conn -Words @('/login', "=name=$User", "=password=$Password")) }
    catch {
        Disconnect-RouterOs $conn
        throw "Помилка авторизації API ($User@$Address): $($_.Exception.Message -replace '\s+\[.*$', '')"
    }
    return $conn
}

function Disconnect-RouterOs {
    param($Connection)
    if ($null -eq $Connection) { return }
    try { $Connection.Stream.Close() } catch { }
    try { $Connection.Client.Close() } catch { }
}

# High level: returns array of hashtables (rows).
function Invoke-Ros {
    param(
        [Parameter(Mandatory, Position = 0)]$Connection,
        [Parameter(Mandatory, Position = 1)][string]$Command,
        [System.Collections.IDictionary]$Arguments,
        [string[]]$Query,
        [string[]]$Proplist,
        [int]$TimeoutMs = 0,
        [switch]$PassDone
    )
    $words = New-Object System.Collections.Generic.List[string]
    $words.Add($Command)
    if ($Arguments) { foreach ($k in $Arguments.Keys) { $words.Add("=$k=$($Arguments[$k])") } }
    if ($Proplist) { $words.Add("=.proplist=$($Proplist -join ',')") }
    if ($Query) { foreach ($q in $Query) { $words.Add($q) } }
    $w = $words.ToArray()
    if ($Command -notmatch '/(print|login|monitor|read|inspect)$') {
        Write-OvpnLog -Level CMD -Message (Format-RosWordsForLog $w)
    }
    $r = Invoke-RosRaw -Connection $Connection -Words $w -TimeoutMs $TimeoutMs
    if ($PassDone) { return $r }
    return , $r.Rows
}

# Returns the =ret= value of a command (e.g. .id from /add).
function Invoke-RosRet {
    param([Parameter(Mandatory, Position = 0)]$Connection, [Parameter(Mandatory, Position = 1)][string]$Command,
          [System.Collections.IDictionary]$Arguments, [int]$TimeoutMs = 0)
    $r = Invoke-Ros $Connection $Command -Arguments $Arguments -TimeoutMs $TimeoutMs -PassDone
    return $r.Done['ret']
}

function Get-RosFirst {
    param([Parameter(Mandatory, Position = 0)]$Connection, [Parameter(Mandatory, Position = 1)][string]$Command, [string[]]$Query)
    $rows = Invoke-Ros $Connection $Command -Query $Query
    if ($rows.Count -gt 0) { return $rows[0] }
    return $null
}

# ---------------------------------------------------------------- files
function Get-RosFile {
    param($Connection, [string]$Name)
    return Get-RosFirst $Connection '/file/print' -Query "?name=$Name"
}

function Wait-RosFile {
    param($Connection, [string]$Name, [int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $lastSize = -1
    while ((Get-Date) -lt $deadline) {
        $f = Get-RosFile $Connection $Name
        if ($f) {
            $size = [long]("0" + ($f['size'] -replace '[^0-9]', ''))
            if ($size -gt 0 -and $size -eq $lastSize) { return $f }
            $lastSize = $size
        }
        Start-Sleep -Milliseconds 700
    }
    throw "Файл '$Name' не з'явився на роутері за $TimeoutSec с"
}

# Reads a file from the router via /file/read (RouterOS 7.13+). Needs policy 'ftp' for the API user.
function Read-RosFile {
    param($Connection, [string]$Name)
    $f = Wait-RosFile $Connection $Name
    $size = [long]("0" + ($f['size'] -replace '[^0-9]', ''))
    $sb = New-Object System.Text.StringBuilder
    $off = 0
    while ($off -lt $size) {
        $r = Invoke-Ros $Connection '/file/read' -Arguments ([ordered]@{ file = $Name; offset = $off; 'chunk-size' = 32768 }) -PassDone
        $data = $null
        if ($r.Rows.Count -gt 0) { $data = $r.Rows[0]['data'] }
        if (-not $data) { $data = $r.Done['data'] }
        if (-not $data) { break }
        [void]$sb.Append($data)
        $off += $data.Length
    }
    if ($sb.Length -lt $size) { throw "Файл '$Name' прочитано не повністю ($($sb.Length) з $size байт)" }
    return $sb.ToString()
}

function Remove-RosFile {
    param($Connection, [string]$Name)
    $f = Get-RosFile $Connection $Name
    if ($f) { [void](Invoke-Ros $Connection '/file/remove' -Arguments ([ordered]@{ '.id' = $f['.id'] })) }
}

# Runs an item command trying '.id' first, then 'numbers'/'number' (RouterOS API differs per command).
function Invoke-RosItemCommand {
    param($Connection, [string]$Command, [string]$Id, [System.Collections.IDictionary]$Arguments, [int]$TimeoutMs = 0)
    $lastErr = $null
    foreach ($key in @('.id', 'numbers', 'number')) {
        $a = [ordered]@{ $key = $Id }
        if ($Arguments) { foreach ($k in $Arguments.Keys) { $a[$k] = $Arguments[$k] } }
        try { return (Invoke-Ros $Connection $Command -Arguments $a -TimeoutMs $TimeoutMs -PassDone) }
        catch {
            $lastErr = $_
            if ($_.Exception.Message -notmatch 'unknown parameter|missing value|no such item|expected') { throw }
        }
    }
    throw $lastErr
}

Export-ModuleMember -Function Write-OvpnLog, Set-OvpnStep, Connect-RouterOs, Disconnect-RouterOs, Invoke-Ros, Invoke-RosRet, Invoke-RosRaw,
    Get-RosFirst, Get-RosFile, Wait-RosFile, Read-RosFile, Remove-RosFile, Invoke-RosItemCommand, Get-RosEncoding
