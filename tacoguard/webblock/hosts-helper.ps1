# TacoGuard hosts helper. Runs with administrator rights, only after you said Yes to Windows' prompt.
# TacoGuard installs it into "<Program Files>\TacoGuard" (only administrators can change files there)
# and runs it with Windows PowerShell:
#   -Action apply -List <file> -Sha256 <hex>   TacoGuard's block becomes "0.0.0.0 <name>" per name
#   -Action remove                             TacoGuard's block is taken out
# Only the lines between the BEGIN and END markers are TacoGuard's; every other byte of the hosts file
# stays as it was (encoding and line endings too). It uses only .NET (no PowerShell modules), writes
# nothing outside the hosts file's folder, and answers only with its exit code:
#   0 done  2 bad request  3 bad list  4 list checksum mismatch  5 the write was blocked or denied
#   6 the hosts file could not be read  7 the file was changed back at once  9 unexpected problem
param([string]$Action = '', [string]$List = '', [string]$Sha256 = '')
$ErrorActionPreference = 'Stop'
$HostsPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'drivers\etc\hosts')
$FlushDns = $true
$Begin = '# BEGIN TacoGuard (do not edit this block)'
$End = '# END TacoGuard'
$Note = '# Added by TacoGuard'
$MaxList = 8388608
$MaxNames = 100000
$NameRx = [System.Text.RegularExpressions.Regex]::new('^(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})\z')
$KeepRx = [System.Text.RegularExpressions.Regex]::new('(?:^|\.)(?:microsoft\.com|windows\.com|windowsupdate\.com|live\.com|microsoftonline\.com|office\.com|office365\.com|microsoft365\.com|msftconnecttest\.com|msftncsi\.com|github\.com|abuse\.ch)\z')

function TgSha([byte[]]$Bytes) {
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $h.Dispose() }
}

function TgEncoding([string]$Kind) {
    if ($Kind -ceq 'utf16le') { return [System.Text.UnicodeEncoding]::new($false, $false, $true) }
    if ($Kind -ceq 'utf16be') { return [System.Text.UnicodeEncoding]::new($true, $false, $true) }
    if ($Kind -ceq 'latin1') { return [System.Text.Encoding]::GetEncoding(28591) }
    return [System.Text.UTF8Encoding]::new($false, $true)
}

function TgPrefix([string]$Kind) {
    if ($Kind -ceq 'utf8bom') { return , [byte[]](0xEF, 0xBB, 0xBF) }
    if ($Kind -ceq 'utf16le') { return , [byte[]](0xFF, 0xFE) }
    if ($Kind -ceq 'utf16be') { return , [byte[]](0xFE, 0xFF) }
    return , [byte[]]@()
}

try {
    if ($Action -cne 'apply' -and $Action -cne 'remove') { exit 2 }
    $names = $null
    if ($Action -ceq 'apply') {
        if ($Sha256 -cnotmatch '^[0-9a-f]{64}$') { exit 2 }
        if (-not $List -or $List.StartsWith('\\') -or -not [System.IO.Path]::IsPathRooted($List)) { exit 3 }
        if (-not [System.IO.File]::Exists($List)) { exit 3 }
        $bad = [System.IO.FileAttributes]::ReparsePoint -bor [System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::Device
        if ([System.IO.File]::GetAttributes($List) -band $bad) { exit 3 }
        $size = [System.IO.FileInfo]::new($List).Length
        if ($size -lt 1 -or $size -gt $MaxList) { exit 3 }
        $listBytes = [System.IO.File]::ReadAllBytes($List)
        if ($listBytes.Length -lt 1 -or $listBytes.Length -gt $MaxList) { exit 3 }
        if ((TgSha $listBytes) -cne $Sha256) { exit 4 }
        $listText = [System.Text.Encoding]::ASCII.GetString($listBytes)
        if (-not $listText.EndsWith([string][char]10)) { exit 3 }
        $names = $listText.Substring(0, $listText.Length - 1).Split([char]10)
        if ($names.Count -gt $MaxNames) { exit 3 }
        foreach ($n in $names) {
            if (-not $NameRx.IsMatch($n) -or $KeepRx.IsMatch($n)) { exit 3 }
        }
    }

    # ---- read the hosts file -------------------------------------------------------------------
    $raw = [byte[]]@()
    try {
        if ([System.IO.File]::Exists($HostsPath)) { $raw = [System.IO.File]::ReadAllBytes($HostsPath) }
    } catch { exit 6 }
    $kind = 'utf8'
    $skip = 0
    if ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF) { $kind = 'utf8bom'; $skip = 3 }
    elseif ($raw.Length -ge 2 -and $raw[0] -eq 0xFF -and $raw[1] -eq 0xFE) { $kind = 'utf16le'; $skip = 2 }
    elseif ($raw.Length -ge 2 -and $raw[0] -eq 0xFE -and $raw[1] -eq 0xFF) { $kind = 'utf16be'; $skip = 2 }
    try {
        $text = (TgEncoding $kind).GetString($raw, $skip, $raw.Length - $skip)
    } catch {
        if ($kind -ceq 'utf16le' -or $kind -ceq 'utf16be') { exit 6 }
        $kind = 'latin1'                       # not UTF-8: every byte kept as it is
        $skip = 0
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($raw)
    }

    # ---- split it: the lines outside TacoGuard's block(s), and where the block was ---------------
    $lines = [System.Text.RegularExpressions.Regex]::Matches($text, '[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+\z')
    $outside = [System.Collections.Generic.List[string]]::new()
    $at = -1
    $i = 0
    $count = $lines.Count
    while ($i -lt $count) {
        $bare = $lines[$i].Value.Trim()
        if ($bare -ceq $Begin) {
            if ($at -lt 0) { $at = $outside.Count }
            $j = $i + 1
            while ($j -lt $count -and $lines[$j].Value.Trim() -cne $End) { $j++ }
            if ($j -lt $count) { $i = $j + 1; continue }
            $j = $i + 1                        # no END line: take only lines in TacoGuard's own format
            while ($j -lt $count) {
                $b = $lines[$j].Value.Trim()
                $parts = $b.Split([char[]](32, 9), [System.StringSplitOptions]::RemoveEmptyEntries)
                if (($parts.Count -eq 2 -and $parts[0] -ceq '0.0.0.0') -or $b.StartsWith($Note)) { $j++; continue }
                break
            }
            $i = $j
            continue
        }
        if ($bare -ceq $End) { $i++; continue }
        $outside.Add($lines[$i].Value)
        $i++
    }
    $hadBlock = ($at -ge 0)

    # ---- the new text ----------------------------------------------------------------------------
    $crlf = [System.Text.RegularExpressions.Regex]::Matches($text, '\r\n').Count
    $lf = [System.Text.RegularExpressions.Regex]::Matches($text, '\n').Count - $crlf
    $nl = [string][char]13 + [string][char]10
    if ($crlf -eq 0 -and $lf -gt 0) { $nl = [string][char]10 }
    $sb = [System.Text.StringBuilder]::new()
    if ($null -eq $names) {
        foreach ($ln in $outside) { [void]$sb.Append($ln) }
    } else {
        $block = [System.Text.StringBuilder]::new()
        [void]$block.Append($Begin).Append($nl)
        [void]$block.Append($Note).Append(' ').Append([DateTime]::Now.ToString('yyyy-MM-dd'))
        [void]$block.Append(" from Phishing.Database and URLhaus. Remove it in TacoGuard's Settings, not by hand.").Append($nl)
        foreach ($n in $names) { [void]$block.Append('0.0.0.0 ').Append($n).Append($nl) }
        [void]$block.Append($End).Append($nl)
        $blockText = $block.ToString()
        if ($at -lt 0) {
            $at = $outside.Count
            if ($at -gt 0) {
                $last = $outside[$at - 1]
                if (-not ($last.EndsWith([string][char]10) -or $last.EndsWith([string][char]13))) { $outside[$at - 1] = $last + $nl }
                if ($outside[$at - 1].Trim() -cne '') { $blockText = $nl + $blockText }
            }
        } elseif ($at -gt 0) {
            $prev = $outside[$at - 1]
            if (-not ($prev.EndsWith([string][char]10) -or $prev.EndsWith([string][char]13))) { $outside[$at - 1] = $prev + $nl }
        }
        for ($k = 0; $k -lt $at; $k++) { [void]$sb.Append($outside[$k]) }
        [void]$sb.Append($blockText)
        for ($k = $at; $k -lt $outside.Count; $k++) { [void]$sb.Append($outside[$k]) }
    }
    $ms = [System.IO.MemoryStream]::new()
    [byte[]]$pre = TgPrefix $kind
    $ms.Write($pre, 0, $pre.Length)
    $body = (TgEncoding $kind).GetBytes($sb.ToString())
    $ms.Write($body, 0, $body.Length)
    $new = $ms.ToArray()
    $newSha = TgSha $new
    if ($newSha -ceq (TgSha $raw)) { exit 0 }        # nothing to change

    # ---- write it: a copy of the original once (as it was before TacoGuard's first block), then
    # the new file swapped in ------------------------------------------------------------------------
    $etc = [System.IO.Path]::GetDirectoryName($HostsPath)
    $backup = [System.IO.Path]::Combine($etc, 'hosts.tacoguard-original')
    $tmp = [System.IO.Path]::Combine($etc, 'hosts.tacoguard-new')
    try {
        if (-not $hadBlock -and -not [System.IO.File]::Exists($backup)) {
            [System.IO.File]::WriteAllBytes($tmp, $raw)
            [System.IO.File]::Move($tmp, $backup)
        }
        [System.IO.File]::WriteAllBytes($tmp, $new)
        if ([System.IO.File]::Exists($HostsPath)) {
            [System.IO.File]::Replace($tmp, $HostsPath, [NullString]::Value)
        } else {
            [System.IO.File]::Move($tmp, $HostsPath)
        }
    } catch {
        try { if ([System.IO.File]::Exists($tmp)) { [System.IO.File]::Delete($tmp) } } catch { }
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception -is [System.IO.IOException] -or
            $_.Exception.InnerException -is [System.UnauthorizedAccessException] -or
            $_.Exception.InnerException -is [System.IO.IOException]) { exit 5 }
        exit 9
    }
    try { $after = [System.IO.File]::ReadAllBytes($HostsPath) } catch { exit 7 }
    if ((TgSha $after) -cne $newSha) { exit 7 }

    if ($FlushDns) {
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new([System.IO.Path]::Combine([Environment]::SystemDirectory, 'ipconfig.exe'), '/flushdns')
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            [void]$p.WaitForExit(60000)
        } catch { }
    }
    exit 0
} catch {
    exit 9
}
