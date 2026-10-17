# Run directly with pwsh -NoProfile -File. No VS Code or SSH process is started.
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot '..\..\scripts\cybergym-windows.ps1'
$profiles = Join-Path $env:TEMP ("cybergym-ui-preflight-test-" + [guid]::NewGuid().ToString('N'))
$runId = 'preflight-test'
$taskId = 'synthetic:profile-test'
$hostAlias = 'cybergym-preflight-test'
$port = 22599
$runKey = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([text.encoding]::UTF8.GetBytes($runId))).Substring(0, 24).ToLowerInvariant()
$taskKey = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([text.encoding]::UTF8.GetBytes($taskId))).Substring(0, 24).ToLowerInvariant()
$root = Join-Path $profiles "cybergym-$runKey-$taskKey"
$baseArgs = @{Preflight=$true; RunId=$runId; TaskId=$taskId; RemoteHost=$hostAlias; Port=$port; ProfilesDir=$profiles}
try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $rejected = $false
    try { & $launcher @baseArgs | Out-Null }
    catch {
        if ($_ -notmatch 'profile prerequisites') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'missing profile did not fail closed' }
    $settingsPath = Join-Path $root 'user-data\User\settings.json'
    New-Item -ItemType Directory -Force -Path (Split-Path $settingsPath -Parent) | Out-Null
    @{ 'remote.SSH.configFile' = (Join-Path $root 'ssh-config'); 'remote.SSH.remotePlatform' = @{ $hostAlias = 'linux' }; 'extensions.autoUpdate' = 'off'; 'extensions.autoCheckUpdates' = $false } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $settingsPath -Encoding utf8
    Set-Content -LiteralPath (Join-Path $root 'ssh-config') -Value "Host $hostAlias`n    HostName 127.0.0.1`n    Port $port`n    UserKnownHostsFile $(Join-Path $root 'known_hosts')`n    StrictHostKeyChecking yes`n" -Encoding ascii
    Set-Content -LiteralPath (Join-Path $root 'known_hosts') -Value "[127.0.0.1]:$port ssh-ed25519 AAAA" -Encoding ascii
    $entries = @(
        @{id='ms-vscode-remote.remote-ssh'; version='0.128.0'; folder='ms-vscode-remote.remote-ssh-0.128.0'},
        @{id='ms-vscode-remote.remote-ssh-edit'; version='0.87.0'; folder='ms-vscode-remote.remote-ssh-edit-0.87.0'},
        @{id='ms-vscode.remote-explorer'; version='0.5.0'; folder='ms-vscode.remote-explorer-0.5.0'}
    )
    $extRoot = Join-Path $root 'extensions'
    New-Item -ItemType Directory -Force -Path $extRoot | Out-Null
    foreach ($entry in $entries) {
        $dir = Join-Path $extRoot $entry.folder
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        @{name=($entry.id -split '\.')[-1]; publisher=($entry.id -split '\.')[0]; version=$entry.version} |
            ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $dir 'package.json') -Encoding utf8
    }
    @($entries | ForEach-Object { @{identifier=@{id=$_.id}; version=$_.version; relativeLocation=$_.folder} }) |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $extRoot 'extensions.json') -Encoding utf8
    & $launcher @baseArgs | Out-Null
    $badPackage = Join-Path $extRoot 'ms-vscode-remote.remote-ssh-0.128.0\package.json'
    $originalPackage = Get-Content -LiteralPath $badPackage -Raw
    $originalPackage.Replace('0.128.0', '0.129.0') | Set-Content -LiteralPath $badPackage -Encoding utf8
    $versionRejected = $false
    try { & $launcher @baseArgs | Out-Null }
    catch {
        if ($_ -notmatch 'profile prerequisites') { throw }
        $versionRejected = $true
    }
    if (-not $versionRejected) { throw 'changed extension version did not fail closed' }
    Set-Content -LiteralPath $badPackage -Value $originalPackage -Encoding utf8
    $externalHosts = Join-Path $profiles 'task-known-hosts'
    Move-Item -LiteralPath (Join-Path $root 'known_hosts') -Destination $externalHosts
    Set-Content -LiteralPath (Join-Path $root 'ssh-config') -Value "Host $hostAlias`n    HostName 127.0.0.1`n    Port $port`n    UserKnownHostsFile $externalHosts`n    StrictHostKeyChecking yes`n" -Encoding ascii
    & $launcher @baseArgs | Out-Null
    Write-Host 'Windows UI profile preflight: missing profile rejected, prepared pinned extensions accepted.'
} finally {
    $resolved = [IO.Path]::GetFullPath($profiles)
    $tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'refusing to clean test path outside TEMP'
    }
    if (Test-Path -LiteralPath $profiles) { Remove-Item -LiteralPath $profiles -Recurse -Force }
}
