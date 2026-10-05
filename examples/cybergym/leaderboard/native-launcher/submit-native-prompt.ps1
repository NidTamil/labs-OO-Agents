param(
    [Parameter(Mandatory = $true)][string]$RemoteAlias,
    [Parameter(Mandatory = $true)][string]$ProfileDirectory,
    [Parameter(Mandatory = $true)][string]$ControllerReceipt,
    [Parameter(Mandatory = $true)][string]$LaunchId,
    [Parameter(Mandatory = $true)][string]$AuditDirectory
)

# Claude Code 2.1.289 places initialPrompt in its webview composer. Its public
# command does not submit the message. This host-only action is deliberately
# narrow: one pinned VS Code profile, one launch receipt, one calibrated layout.
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

$title = "Claude Code - workspace [SSH: $RemoteAlias] - Visual Studio Code"
$windows = @(Get-Process Code -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -ceq $title })
if ($windows.Count -ne 1) {
    throw 'Exactly one isolated Claude composer window is required'
}
$window = $windows[0]
$process = Get-CimInstance Win32_Process -Filter "ProcessId=$($window.Id)"
if (
    $null -eq $process -or
    [string]::IsNullOrWhiteSpace($process.CommandLine) -or
    -not $process.CommandLine.Contains($ProfileDirectory, [StringComparison]::OrdinalIgnoreCase)
) {
    throw 'Claude window is not owned by the pinned isolated VS Code profile'
}

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NativeUi {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint x, uint y, uint data, UIntPtr extra);
}
'@
$rect = New-Object NativeUi+RECT
if (-not [NativeUi]::GetWindowRect($window.MainWindowHandle, [ref]$rect)) {
    throw 'Isolated window geometry unavailable'
}
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
if ($width -ne 1456 -or $height -ne 908) {
    throw 'Uncalibrated native composer layout'
}

$parent = Split-Path -Parent $AuditDirectory
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Controller audit parent directory missing'
}
New-Item -ItemType Directory -Path $AuditDirectory -ErrorAction Stop | Out-Null
$screenshot = Join-Path $AuditDirectory 'pre-submit.png'
$bitmap = [System.Drawing.Bitmap]::new($width, $height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
try {
    $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
    $samples = @(
        $bitmap.GetPixel(1103, 507),
        $bitmap.GetPixel(1102, 520),
        $bitmap.GetPixel(1118, 507)
    )
    foreach ($pixel in $samples) {
        if ($pixel.R -lt 170 -or $pixel.R -gt 230 -or $pixel.G -lt 70 -or $pixel.G -gt 130 -or $pixel.B -lt 40 -or $pixel.B -gt 100) {
            throw 'Enabled Claude Send button was not observed at the calibrated position'
        }
    }
    $bitmap.Save($screenshot, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $graphics.Dispose()
    $bitmap.Dispose()
}

$event = [ordered]@{
    schema_version = 1
    event = 'ui_send_reserved'
    launch_id = $LaunchId
    prompt_sha256 = $receipt.prompt_sha256
    remote_alias = $RemoteAlias
    vscode_pid = $window.Id
    window_title = $title
    window_width = $width
    window_height = $height
    button_samples_rgb = @($samples | ForEach-Object { @($_.R, $_.G, $_.B) })
    screenshot_sha256 = (Get-FileHash -LiteralPath $screenshot -Algorithm SHA256).Hash.ToLowerInvariant()
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

$shell = New-Object -ComObject WScript.Shell
if (-not $shell.AppActivate([int]$window.Id)) {
    throw 'Could not activate the reserved isolated window'
}
Start-Sleep -Milliseconds 200
$current = New-Object NativeUi+RECT
if (-not [NativeUi]::GetWindowRect($window.MainWindowHandle, [ref]$current) -or
    $current.Left -ne $rect.Left -or $current.Top -ne $rect.Top -or
    $current.Right -ne $rect.Right -or $current.Bottom -ne $rect.Bottom) {
    throw 'Isolated window moved after reservation'
}
if (-not [NativeUi]::SetCursorPos($rect.Left + 1112, $rect.Top + 514)) {
    throw 'Could not position cursor over the calibrated Send button'
}
Start-Sleep -Milliseconds 150
[NativeUi]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
[NativeUi]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
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
