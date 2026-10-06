# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
  Own a CyberGym VS Code window and SSH tunnel for one campaign task.
.DESCRIPTION
  -Close and -Reap select only this run's unique profile path and SSH ownership
  markers. A recorded PID alone never authorizes termination. -Force replaces
  only resources belonging to the supplied run.
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Open', Mandatory)] [switch] $Open,
    [Parameter(ParameterSetName = 'Close', Mandatory)] [switch] $Close,
    [Parameter(ParameterSetName = 'Reap', Mandatory)] [switch] $Reap,
    [Parameter(ParameterSetName = 'Status', Mandatory)] [switch] $Status,
    [Parameter(ParameterSetName = 'Open', Mandatory)]
    [Parameter(ParameterSetName = 'Close', Mandatory)]
    [Parameter(ParameterSetName = 'Reap', Mandatory)]
    [ValidateNotNullOrEmpty()] [string] $RunId,
    [Parameter(ParameterSetName = 'Open', Mandatory)]
    [Parameter(ParameterSetName = 'Close', Mandatory)]
    [ValidateNotNullOrEmpty()] [string] $TaskId,
    [Parameter(ParameterSetName = 'Open', Mandatory)]
    [Parameter(ParameterSetName = 'Close', Mandatory)]
    [ValidateNotNullOrEmpty()] [string] $RemoteHost,
    [Parameter(ParameterSetName = 'Open', Mandatory)] [ValidateRange(1,65535)] [int] $Port,
    [Parameter(ParameterSetName = 'Open')] [ValidateRange(1,100)] [int] $MaxConcurrent = 1,
    [Parameter(ParameterSetName = 'Open')] [switch] $Force,
    [string] $ProfilesDir = 'D:\GLM\profiles',
    [string] $CodeExe = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe",
    [string] $RemoteHostFqdn = 'sunchaser-20260905'
)

$ErrorActionPreference = 'Stop'

function Get-Key([string] $value) {
    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($value))
    return [Convert]::ToHexString($hash).Substring(0,24).ToLowerInvariant()
}
if ($RunId) {
    $RunKey = Get-Key $RunId
    $Manifest = Join-Path $ProfilesDir "run-windows-$RunKey.json"
}
function Get-UserData([string] $key) {
    return Join-Path $ProfilesDir "cybergym-${RunKey}-${key}\user-data"
}
function Read-Manifest {
    if (-not (Test-Path -LiteralPath $Manifest)) { return @() }
    try {
        $rows = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $rows) { return @() }
        return @($rows)
    } catch {
        throw "Owned window manifest is unreadable: $Manifest"
    }
}
function Write-Manifest([object[]] $rows) {
    if (-not (Test-Path -LiteralPath $ProfilesDir)) {
        New-Item -ItemType Directory -Force -Path $ProfilesDir | Out-Null
    }
    $temp = "$Manifest.$PID.tmp"
    ConvertTo-Json -InputObject @($rows) -Depth 5 | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $Manifest -Force
}
function Test-Owned($proc, [string] $kind, [string] $key, [int] $port) {
    if ($null -eq $proc -or -not $proc.CommandLine) { return $false }
    $line = $proc.CommandLine
    if ($kind -eq 'window') {
        return ($proc.Name -eq 'Code.exe' -and $line -notmatch '--type=' -and
            $line -match [regex]::Escape((Get-UserData $key)))
    }
    if ($proc.Name -ne 'ssh.exe' -or
        $line -notmatch [regex]::Escape("CYBERGYM_RUN_KEY=$RunKey") -or
        $line -notmatch [regex]::Escape("CYBERGYM_TASK_KEY=$key") -or
        $line -notmatch [regex]::Escape("root@$RemoteHostFqdn.cinnamon-gamut.ts.net")) {
        return $false
    }
    return ($port -eq 0 -or
        $line -match [regex]::Escape("127.0.0.1:${port}:127.0.0.1:${port}"))
}
function Get-Owned([string] $kind, [string] $key, [int] $port) {
    $name = if ($kind -eq 'window') { 'Code.exe' } else { 'ssh.exe' }
    @(Get-CimInstance Win32_Process -Filter "Name='$name'" |
        Where-Object { Test-Owned $_ $kind $key $port })
}
function Stop-Owned($record, [string] $kind, [string] $key, [int] $port) {
    $procId = [int]$record.ProcessId
    $live = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
    if (-not (Test-Owned $live $kind $key $port)) { return $false }
    if ($live.CreationDate.ToUniversalTime().ToString('o') -ne
        $record.CreationDate.ToUniversalTime().ToString('o')) { return $false }
    try {
        # Hold the verified process handle so PID reuse cannot redirect Kill().
        $handle = Get-Process -Id $procId -ErrorAction Stop
        if ($handle.StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff') -ne
            $live.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff')) {
            return $false
        }
        $handle.Kill()
        Write-Host "  killed owned $kind (pid $procId)"
        return $true
    } catch { return $false }
}
function Close-Task([string] $key, [int] $port) {
    $count = 0
    foreach ($kind in @('window', 'tunnel')) {
        foreach ($proc in Get-Owned $kind $key $port) {
            if (Stop-Owned $proc $kind $key $port) { $count++ }
        }
    }
    if (@(Get-Owned 'window' $key $port).Count -or
        @(Get-Owned 'tunnel' $key $port).Count) {
        throw "Owned task processes remain live for $key; manifest retained for retry"
    }
    return $count
}
function Invoke-Reap {
    $rows = @(Read-Manifest)
    $keys = @($rows | ForEach-Object { $_.taskKey } | Where-Object { $_ })
    # Discover crash orphans even if PID capture did not finish.
    foreach ($proc in Get-CimInstance Win32_Process -Filter "Name='Code.exe' OR Name='ssh.exe'") {
        if (-not $proc.CommandLine) { continue }
        if ($proc.CommandLine -match "cybergym-$RunKey-([0-9a-f]{24})\\user-data" -or
            ($proc.CommandLine -match [regex]::Escape("CYBERGYM_RUN_KEY=$RunKey") -and
             $proc.CommandLine -match 'CYBERGYM_TASK_KEY=([0-9a-f]{24})')) {
            $keys += $matches[1]
        }
    }
    $count = 0
    foreach ($key in @($keys | Select-Object -Unique)) { $count += Close-Task $key 0 }
    Write-Manifest @()
    Write-Host "Reap for run $RunId complete: $count owned process(es) killed."
}
function Invoke-Close {
    $rows = @(Read-Manifest)
    $key = Get-Key $TaskId
    $row = $rows | Where-Object { $_.taskKey -eq $key -and $_.remoteHost -eq $RemoteHost } | Select-Object -First 1
    if (-not $row) { throw "No owned entry for task $TaskId on $RemoteHost in run $RunId" }
    $count = Close-Task $key ([int]$row.port)
    Write-Manifest @($rows | Where-Object { $_.taskKey -ne $key })
    Write-Host "Closed $RemoteHost for run $RunId task ${TaskId}: $count owned process(es) killed."
}
function Invoke-Open {
    if (-not (Test-Path -LiteralPath $CodeExe)) { throw "VS Code not found at $CodeExe" }
    $rows = @(Read-Manifest)
    $key = Get-Key $TaskId
    if (@($rows | Where-Object { $_.taskKey -eq $key }).Count) {
        throw "Task $TaskId already has an owned window entry"
    }
    if ($rows.Count -ge $MaxConcurrent) {
        if (-not $Force) { throw "Run $RunId has reached MaxConcurrent=$MaxConcurrent" }
        Invoke-Reap
        $rows = @()
    }
    $userData = Get-UserData $key
    $extDir = Join-Path (Split-Path $userData -Parent) 'extensions'
    $sshKnown = Join-Path $env:APPDATA 'tailscale\ssh_known_hosts'
    $tailscale = 'C:\Program Files\Tailscale\tailscale.exe'
    $fwd = "127.0.0.1:${Port}:127.0.0.1:${Port}"
    $row = [pscustomobject]@{
        runId = $RunId; taskId = $TaskId; taskKey = $key; remoteHost = $RemoteHost
        port = $Port; userDataDir = $userData; tunnelPid = 0; windowHostPid = 0
        openedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    # Reserve ownership before either process starts, so -Reap can find crash orphans.
    Write-Manifest @($rows + $row)
    try {
        $sshArgs = @(
            '-o', "UserKnownHostsFile=$sshKnown", '-o', 'UpdateHostKeys=no', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'CanonicalizeHostname=no', '-o', "ProxyCommand=`"$tailscale`" nc %h %p",
            '-o', "SetEnv=CYBERGYM_RUN_KEY=$RunKey", '-o', "SetEnv=CYBERGYM_TASK_KEY=$key",
            "root@$RemoteHostFqdn.cinnamon-gamut.ts.net", '-N', '-L', $fwd
        )
        $ssh = Start-Process -FilePath "$env:WINDIR\System32\OpenSSH\ssh.exe" -ArgumentList $sshArgs -PassThru -WindowStyle Hidden
        $row.tunnelPid = $ssh.Id
        Write-Manifest @($rows + $row)
        $codeArgs = @(
            '--user-data-dir', $userData, '--extensions-dir', $extDir, '--new-window',
            "--folder-uri=vscode-remote://ssh-remote+$RemoteHost/workspace"
        )
        $code = Start-Process -FilePath $CodeExe -ArgumentList $codeArgs -PassThru -WindowStyle Normal
        $row.windowHostPid = $code.Id
        Write-Manifest @($rows + $row)
        Write-Host "Opened $RemoteHost for run $RunId task $TaskId (window pid $($code.Id), tunnel pid $($ssh.Id))."
    } catch {
        Close-Task $key $Port | Out-Null
        Write-Manifest $rows
        throw
    }
}
function Show-Status {
    if (-not (Test-Path -LiteralPath $ProfilesDir)) { Write-Host 'No CyberGym profile directory'; return }
    Get-ChildItem -LiteralPath $ProfilesDir -Filter 'run-windows-*.json' -File |
        ForEach-Object {
            Write-Host $_.FullName
            try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json |
                Format-Table runId, taskId, remoteHost, port, windowHostPid, tunnelPid }
            catch { Write-Warning "Unreadable manifest: $($_.FullName)" }
        }
}
switch ($PSCmdlet.ParameterSetName) {
    'Open' { Invoke-Open }
    'Close' { Invoke-Close }
    'Reap' { Invoke-Reap }
    'Status' { Show-Status }
}
