# Omni Cyber Guard - scan pipeline diagnostic
#
# Run from the repository root in PowerShell:
#
#     .\scripts\diagnose-scanning.ps1
#
# Reports which services are running, whether a Celery worker is actually
# consuming the scan queue, whether nmap inside the worker has the raw-socket
# capability it needs, and whether the worker can see the LAN you are trying to
# scan. Reads only - it starts nothing and changes nothing.

$ErrorActionPreference = "Continue"

function Section($t) {
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor DarkGray
    Write-Host $t -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor DarkGray
}

Section "1. Your laptop's network (this is what you should be scanning)"
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object IPAddress, PrefixLength, InterfaceAlias |
    Format-Table -AutoSize

Section "2. Compose services"
docker compose ps

Section "3. Is the beat scheduler present?"
$ps = docker compose ps --services 2>$null
if ($ps -contains "beat") {
    Write-Host "beat service is defined." -ForegroundColor Green
    $running = docker compose ps --services --filter "status=running" 2>$null
    if ($running -contains "beat") {
        Write-Host "beat is RUNNING." -ForegroundColor Green
    } else {
        Write-Host "beat is defined but NOT running - scheduled work is dead." -ForegroundColor Yellow
    }
} else {
    Write-Host "No beat service. The containers predate the fix - rebuild." -ForegroundColor Red
}

Section "4. Is a worker actually consuming the queue?"
docker compose exec -T worker celery -A app.core.celery_app inspect ping 2>&1 | Select-Object -First 20

Section "5. Registered tasks (scan task must be listed)"
docker compose exec -T worker celery -A app.core.celery_app inspect registered 2>&1 |
    Select-String -Pattern "scan|discovery" | Select-Object -First 15

Section "6. Worker log - last 60 lines"
docker compose logs --tail=60 worker 2>&1

Section "7. nmap inside the worker"
docker compose exec -T worker sh -c "which nmap && nmap --version | head -2 && getcap /usr/bin/nmap && id" 2>&1

Section "8. What network does the worker see?"
docker compose exec -T worker sh -c "ip -4 addr show | grep -E 'inet ' ; echo '--- routes ---' ; ip route" 2>&1

Section "9. Can the worker reach your LAN gateway?"
$gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if ($gw) {
    Write-Host "Your default gateway is $gw"
    docker compose exec -T worker sh -c "nmap -sn -n --send-ip $gw 2>&1 | tail -5" 2>&1
} else {
    Write-Host "Could not determine a default gateway." -ForegroundColor Yellow
}

Section "10. Redis queue depth (jobs waiting with nobody to take them)"
docker compose exec -T redis redis-cli LLEN celery 2>&1

Write-Host ""
Write-Host "Copy everything above and paste it back." -ForegroundColor Green
