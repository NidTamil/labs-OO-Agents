# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
param(
    [Parameter(Mandatory = $true)][string]$RemoteAlias,
    [Parameter(Mandatory = $true)][string]$ProfileDirectory,
    [Parameter(Mandatory = $true)][string]$ControllerReceipt,
    [Parameter(Mandatory = $true)][string]$LaunchId,
    [Parameter(Mandatory = $true)][string]$AuditDirectory,
    [ValidateRange(1, 120)][int]$ReadyTimeoutSeconds = 120
)

# Claude Code 2.1.289 places initialPrompt in its webview composer. Its public
# command does not submit the message. This host-only action is deliberately
# narrow: one pinned VS Code profile, one launch receipt, and the matching
# accessible Claude Code composer. The prompt is hashed, never copied to audit.
# A later gateway request, not this UI event, proves that Claude sent anything.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($RemoteAlias -notmatch '^[a-z][a-z0-9-]{1,63}$' -or $LaunchId -notmatch '^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$') {
    throw 'Invalid isolated launch identity'
}
foreach ($path in @($ProfileDirectory, $ControllerReceipt, $AuditDirectory)) {
    if (-not [IO.Path]::IsPathFullyQualified($path) -or -not $path.StartsWith('D:\GLM\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Native UI custody paths must be absolute under D:\GLM'
    }
}
if (Test-Path -LiteralPath $AuditDirectory) {
    throw 'Native UI action already reserved'
}
$receipt = Get-Content -LiteralPath $ControllerReceipt -Raw | ConvertFrom-Json -AsHashtable
if (
    $receipt.event -ne 'launch_reserved' -or
    $receipt.launch_id -ne $LaunchId -or
    $receipt.session_id -ne $null -or
    $receipt.prompt_sha256 -notmatch '^[a-f0-9]{64}$'
) {
    throw 'Controller launch receipt is not the expected pre-model reservation'
}

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$title = "Claude Code - workspace [SSH: $RemoteAlias] - Visual Studio Code"
# Remote-SSH and the webview load asynchronously. Wait only before the
# durable one-shot UI reservation; a post-reservation retry could click twice.
$readyDeadline = [DateTime]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
while ($true) {
try {
    $windows = @(Get-Process Code -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -ceq $title })
    if ($windows.Count -eq 0) { throw 'Claude UI not ready: window' }
    if ($windows.Count -ne 1) { throw 'Exactly one isolated Claude composer window is required' }
    $window = $windows[0]
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($window.Id)"
    if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.CommandLine)) {
        throw 'Claude UI not ready: window process'
    }
    if (-not $process.CommandLine.Contains($ProfileDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Claude window is not owned by the pinned isolated VS Code profile'
    }
$root = [System.Windows.Automation.AutomationElement]::FromHandle($window.MainWindowHandle)
$documents = $root.FindAll(
    [System.Windows.Automation.TreeScope]::Descendants,
    [System.Windows.Automation.AndCondition]::new(@(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Document),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, 'Claude Code')
    ))
)
if ($documents.Count -eq 0) { throw 'Claude UI not ready: document' }
if ($documents.Count -ne 1) { throw 'Exactly one accessible Claude Code document required' }
$document = $documents[0]
$inputs = $document.FindAll(
    [System.Windows.Automation.TreeScope]::Descendants,
    [System.Windows.Automation.AndCondition]::new(@(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Edit),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, 'Message input')
    ))
)
if ($inputs.Count -eq 0) { throw 'Claude UI not ready: message input' }
if ($inputs.Count -ne 1) { throw 'Exactly one Claude message input required' }
$valuePattern = $null
if (-not $inputs[0].TryGetCurrentPattern(
        [System.Windows.Automation.ValuePattern]::Pattern, [ref]$valuePattern)) {
    throw 'Claude UI not ready: message input value'
}
$observedPromptSha256 = [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($valuePattern.Current.Value)
    )
).ToLowerInvariant()
if ($observedPromptSha256 -cne $receipt.prompt_sha256) {
    throw 'Claude UI not ready: reserved prompt'
}
$buttons = $document.FindAll(
    [System.Windows.Automation.TreeScope]::Descendants,
    [System.Windows.Automation.AndCondition]::new(@(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Button),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, 'Send message')
    ))
)
if ($buttons.Count -eq 0) { throw 'Claude UI not ready: Send button' }
if ($buttons.Count -ne 1) { throw 'Exactly one Claude Send button required' }
if (-not $buttons[0].Current.IsEnabled) { throw 'Claude UI not ready: enabled Send button' }
$invokePattern = $null
if (-not $buttons[0].TryGetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern, [ref]$invokePattern)) {
    throw 'Claude UI not ready: Send Invoke action'
}
    break
} catch {
    if ($_.Exception.Message.StartsWith('Claude UI not ready:', [StringComparison]::Ordinal)) {
        if ([DateTime]::UtcNow -ge $readyDeadline) {
            throw "Claude composer did not become ready within $ReadyTimeoutSeconds seconds"
        }
        Start-Sleep -Milliseconds 750
        continue
    }
    throw
}
}

$parent = Split-Path -Parent $AuditDirectory
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Controller audit parent directory missing'
}
New-Item -ItemType Directory -Path $AuditDirectory -ErrorAction Stop | Out-Null

$event = [ordered]@{
    schema_version = 1
    event = 'ui_send_reserved'
    launch_id = $LaunchId
    prompt_sha256 = $receipt.prompt_sha256
    remote_alias = $RemoteAlias
    vscode_pid = $window.Id
    window_title = $title
    composer = 'Claude Code/Message input'
    observed_prompt_sha256 = $observedPromptSha256
    action = 'Claude Code/Send message/InvokePattern'
    provider_request_observed = $false
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
}
$reservation = Join-Path $AuditDirectory 'ui-send-reservation.json'
$encoded = [Text.Encoding]::UTF8.GetBytes(($event | ConvertTo-Json -Depth 8 -Compress))
$stream = [IO.FileStream]::new($reservation, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $stream.Write($encoded, 0, $encoded.Length)
    $stream.Flush($true)
} finally {
    $stream.Dispose()
}

$currentPromptSha256 = [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($valuePattern.Current.Value)
    )
).ToLowerInvariant()
if ($currentPromptSha256 -cne $receipt.prompt_sha256 -or -not $buttons[0].Current.IsEnabled) {
    throw 'Claude composer changed after UI reservation'
}
$invokePattern.Invoke()
$event.event = 'ui_send_attempted'
$event.timestamp_utc = [DateTime]::UtcNow.ToString('o')
$action = Join-Path $AuditDirectory 'ui-send-attempted.json'
$encoded = [Text.Encoding]::UTF8.GetBytes(($event | ConvertTo-Json -Depth 8 -Compress))
$stream = [IO.FileStream]::new($action, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $stream.Write($encoded, 0, $encoded.Length)
    $stream.Flush($true)
} finally {
    $stream.Dispose()
}
Write-Output $action
