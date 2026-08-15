# Omni Cyber Guard  -  install always-on auto-start (Windows)
# Powered by Omni Digital Solution
#
# Run once, from the project root, AFTER .\setup.ps1 has succeeded at least once:
#   .\scripts\install-autostart.ps1
#
# This makes two things happen automatically every time you log in to Windows,
# with no manual steps:
#   1. Docker Desktop launches (which brings back postgres/redis/backend/frontend,
#      since they're already set to `restart: unless-stopped`).
#   2. The native scan worker starts (via a Scheduled Task), so nmap can see
#      your real LAN  -  this can't run inside Docker Desktop on Windows.
#
# Nothing here modifies system files outside your user profile; it only adds
# one Scheduled Task (visible in Task Scheduler under "Omni Cyber Guard") and,
# if possible, flips Docker Desktop's own "start at login" setting.

$ErrorActionPreference = "Stop"
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "    $msg" -ForegroundColor Red }

$root = Split-Path -Parent $PSScriptRoot
$workerScript = Join-Path $root "scripts\start-scan-worker.ps1"

if (-not (Test-Path $workerScript)) {
    Write-Err "Could not find scripts\start-scan-worker.ps1  -  run this from the omni-cyber-guard project root."
    exit 1
}

# --- 1. Try to enable "Start Docker Desktop when you log in" ---
Write-Host "`n==> Docker Desktop auto-start" -ForegroundColor Cyan
$dockerSettingsPath = "$env:APPDATA\Docker\settings.json"
if (Test-Path $dockerSettingsPath) {
    try {
        $settings = Get-Content $dockerSettingsPath -Raw | ConvertFrom-Json
        $settings | Add-Member -NotePropertyName "autoStart" -NotePropertyValue $true -Force
        $settings | ConvertTo-Json -Depth 20 | Set-Content $dockerSettingsPath -Encoding UTF8
        Write-Ok "Enabled 'Start Docker Desktop when you log in'. (Restart Docker Desktop once for it to take effect.)"
    } catch {
        Write-Warn "Couldn't edit Docker Desktop's settings automatically. Please enable it yourself:"
        Write-Warn "Docker Desktop -> Settings (gear icon) -> General -> check 'Start Docker Desktop when you log in'."
    }
} else {
    Write-Warn "Couldn't find Docker Desktop's settings file. Please enable it yourself:"
    Write-Warn "Docker Desktop -> Settings (gear icon) -> General -> check 'Start Docker Desktop when you log in'."
}

# --- 2. Register the scan worker as a Scheduled Task that runs at logon ---
Write-Host "`n==> Scan worker auto-start" -ForegroundColor Cyan

$taskName = "OmniCyberGuard-ScanWorker"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$workerScript`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Description "Omni Cyber Guard  -  starts the real-LAN network scan worker at logon. Powered by Omni Digital Solution." | Out-Null

Write-Ok "Scheduled Task '$taskName' created  -  it will start the scan worker every time you log in."
Write-Ok "You can see/manage it any time in Task Scheduler, or remove it with .\scripts\uninstall-autostart.ps1"

# --- 3. Start it right now too, so you don't have to log out/in to test it ---
Write-Host "`n==> Starting it now" -ForegroundColor Cyan
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2
$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
Write-Ok "Task last run result: $($taskInfo.LastTaskResult) (0 = still running/starting, which is expected)"

Write-Host "`nDone. From now on, after a reboot: log in to Windows, Docker Desktop starts your web app," -ForegroundColor White
Write-Host "and the scan worker starts in the background automatically  -  nothing to run by hand." -ForegroundColor White
Write-Host "Open http://localhost:3000 once Docker Desktop shows all containers running (takes ~30-60s after login)." -ForegroundColor White
