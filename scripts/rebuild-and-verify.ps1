# Omni Cyber Guard - rebuild the stack and verify the scan pipeline end to end.
#
#     .\scripts\rebuild-and-verify.ps1
#
# Your worker container was built 22 hours ago. It predates the nmap capability
# fix, the beat scheduler, the graph tasks and the reachability preflight.
# Because docker-compose bind-mounts ./backend into the container, the source on
# disk is current - but a Celery worker imports its code once at startup and
# never reloads, so the running process still holds the version from when it
# started. That is why 'graph_tasks.rebuild_all_graphs' is missing from its
# registered task list.
#
# This stops everything, rebuilds the images, applies migrations, brings the
# full stack up including beat, and then checks each piece.

$ErrorActionPreference = "Continue"

function Section($t) {
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor DarkGray
    Write-Host $t -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor DarkGray
}

Section "0. Scan jobs as they stand right now (before any change)"
docker compose exec -T postgres psql -U ocg_app -d omni_cyber_guard -c `
  "SELECT id, engine, target_cidr, status, created_at, left(coalesce(error_message,''), 80) AS error FROM scan_jobs ORDER BY created_at DESC LIMIT 10;" 2>&1

Section "1. Stopping the stack"
docker compose down

Section "2. Rebuilding images (this takes a few minutes)"
docker compose build backend frontend
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed. Stopping here - nothing was started." -ForegroundColor Red
    exit 1
}

Section "3. Starting postgres and redis"
docker compose up -d postgres redis
Start-Sleep -Seconds 8

Section "4. Applying database migrations"
docker compose run --rm backend alembic upgrade head 2>&1 | Select-Object -Last 20

Section "5. Starting the full stack"
docker compose up -d
Start-Sleep -Seconds 20

Section "6. Services"
docker compose ps

Section "7. beat must be running (nothing scheduled works without it)"
$running = docker compose ps --services --filter "status=running" 2>$null
if ($running -contains "beat") {
    Write-Host "beat is RUNNING." -ForegroundColor Green
} else {
    Write-Host "beat is NOT running. Check: docker compose logs beat" -ForegroundColor Red
}

Section "8. Worker is consuming, and now knows the new tasks"
docker compose exec -T worker celery -A app.core.celery_app inspect ping 2>&1 | Select-Object -First 5
Write-Host ""
Write-Host "Registered tasks (graph_tasks must appear - it is the marker that the worker is current):"
docker compose exec -T worker celery -A app.core.celery_app inspect registered 2>&1 |
    Select-String -Pattern "graph_tasks|scan_tasks" 

Section "9. nmap raw-socket capability inside the worker"
docker compose exec -T worker sh -c "getcap /usr/bin/nmap; id" 2>&1
Write-Host "Expect: /usr/bin/nmap cap_net_bind_service,cap_net_admin,cap_net_raw=eip"
Write-Host "If getcap prints nothing, the worker will silently fall back to unprivileged scanning."

Section "10. Reachability preflight - what the worker can actually see"
docker compose exec -T worker python -c "from app.services.scan_reachability import assess_target; r = assess_target('192.168.1.0/24'); print('on_link:', r.on_link); print(r.summary); print(); [print(l) for l in r.as_log_lines()]" 2>&1

Section "11. Authorized scope - a scan is refused without one"
docker compose exec -T postgres psql -U ocg_app -d omni_cyber_guard -c `
  "SELECT name, cidr, is_authorized_scope FROM networks ORDER BY created_at DESC LIMIT 10;" 2>&1
Write-Host ""
Write-Host "192.168.1.0/24 must appear here with is_authorized_scope = t."
Write-Host "If it does not, add it under Sites and Networks and mark it authorized;"
Write-Host "the scan will be refused with 403 rather than run."

Write-Host ""
Write-Host "Now start a scan of 192.168.1.0/24 from the Scan Center." -ForegroundColor Green
Write-Host "Then run:  docker compose logs -f worker" -ForegroundColor Green
