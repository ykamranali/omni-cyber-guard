# Omni Cyber Guard  -  remove the always-on auto-start
# Powered by Omni Digital Solution
#
# Undoes what install-autostart.ps1 set up: stops and removes the
# Scheduled Task. Does NOT touch your Docker containers or data  -  run
# `docker compose down` separately if you want to stop those too.

$taskName = "OmniCyberGuard-ScanWorker"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Removed the '$taskName' scheduled task. The scan worker will no longer start automatically at logon." -ForegroundColor Green
} else {
    Write-Host "No '$taskName' scheduled task was found  -  nothing to remove." -ForegroundColor Yellow
}

Write-Host "If you also enabled Docker Desktop's 'Start when you log in', turn that off manually in Docker Desktop -> Settings -> General if you want." -ForegroundColor DarkGray
