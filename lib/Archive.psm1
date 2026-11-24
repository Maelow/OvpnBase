# 7-Zip packaging (portable 7-Zip from tools\7z).

function Get-SevenZip {
    param([string]$ToolsDir)
    $exe = Join-Path $ToolsDir '7z.exe'
    $sfx = Join-Path $ToolsDir '7z.sfx'
    $dll = Join-Path $ToolsDir '7z.dll'
    $missing = @($exe, $sfx, $dll | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missing.Count) {
        $pf = Join-Path $env:ProgramFiles '7-Zip'
        if (Test-Path (Join-Path $pf '7z.exe')) {
            New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
            foreach ($f in @('7z.exe', '7z.dll', '7z.sfx', 'License.txt')) {
                $src = Join-Path $pf $f
                if (Test-Path $src) { Copy-Item -LiteralPath $src -Destination $ToolsDir -Force }
            }
            Write-OvpnLog "7-Zip скопійовано з $pf у $ToolsDir"
        }
        $missing = @($exe, $sfx, $dll | Where-Object { -not (Test-Path -LiteralPath $_) })
        if ($missing.Count) { throw "Не знайдено 7-Zip: $($missing -join ', '). Покладіть 7z.exe, 7z.dll, 7z.sfx у $ToolsDir" }
    }
    return [pscustomobject]@{ Exe = $exe; Sfx = $sfx }
}

function ConvertTo-WinArg {
    param([string]$Arg)
    if ($Arg.Length -gt 0 -and $Arg -notmatch '[\s"]') { return $Arg }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bs = 0
    foreach ($ch in $Arg.ToCharArray()) {
        if ($ch -eq '\') { $bs++; continue }
        if ($ch -eq '"') { [void]$sb.Append(('\' * ($bs * 2 + 1)) + '"'); $bs = 0; continue }
        if ($bs) { [void]$sb.Append('\' * $bs); $bs = 0 }
        [void]$sb.Append($ch)
    }
    [void]$sb.Append('\' * ($bs * 2))
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Invoke-SevenZip {
    param([string]$Exe, [string[]]$Arguments, [string]$WorkDir)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = (($Arguments | ForEach-Object { ConvertTo-WinArg $_ }) -join ' ')
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $safe = ($Arguments | ForEach-Object { if ($_ -like '-p*') { '-p***' } else { $_ } }) -join ' '
    Write-OvpnLog -Level CMD "7z $safe"
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "7-Zip завершився з кодом $($p.ExitCode): $stderr $($stdout.Result | Select-Object -Last 1)" }
    return $stdout.Result
}

# Files must be inside WorkDir; archive stores bare names.
function New-OvpnArchive {
    param(
        [Parameter(Mandatory)]$SevenZip,
        [ValidateSet('Sfx', 'ZipAes', 'ZipCrypto')][string]$Kind,
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string]$WorkDir,
        [Parameter(Mandatory)][string]$Password
    )
    if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }
    $names = $Files | ForEach-Object { Split-Path -Leaf $_ }
    switch ($Kind) {
        'Sfx' { $a = @('a', '-t7z', "-sfx$($SevenZip.Sfx)", '-mx=9', '-mhe=on', "-p$Password", '-y', '--', $OutFile) + $names }
        'ZipAes' { $a = @('a', '-tzip', '-mem=AES256', '-mx=9', "-p$Password", '-y', '--', $OutFile) + $names }
        'ZipCrypto' { $a = @('a', '-tzip', '-mem=ZipCrypto', '-mx=9', "-p$Password", '-y', '--', $OutFile) + $names }
    }
    [void](Invoke-SevenZip -Exe $SevenZip.Exe -Arguments $a -WorkDir $WorkDir)
    # verify: archive opens with password and contains all files
    $list = Invoke-SevenZip -Exe $SevenZip.Exe -Arguments @('t', "-p$Password", '-y', '--', $OutFile) -WorkDir $WorkDir
    if ($list -notmatch 'Everything is Ok') { throw "Перевірка архіву $OutFile не пройшла" }
    $wrong = $null
    try { [void](Invoke-SevenZip -Exe $SevenZip.Exe -Arguments @('t', '-pWRONG-password-check', '-y', '--', $OutFile) -WorkDir $WorkDir); $wrong = 'opened' } catch { }
    if ($wrong) { throw "Архів $OutFile відкривається без правильного пароля!" }
    Write-OvpnLog -Level OK "Архів $(Split-Path -Leaf $OutFile): пароль перевірено"
    return (Get-Item -LiteralPath $OutFile)
}

Export-ModuleMember -Function Get-SevenZip, ConvertTo-WinArg, Invoke-SevenZip, New-OvpnArchive
