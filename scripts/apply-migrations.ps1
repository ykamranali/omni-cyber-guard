# Apply the pending database migrations, then re-check what the scan needs.
#
#     .\scripts\apply-migrations.ps1
#
# The previous run stopped at "Multiple head revisions are present". Two
# migrations had been written against the same parent in parallel - the truth
# pass and the notifications/ticketing work - so the revision graph forked.
# Alembic will not guess which of two heads you meant, so it applied neither and
# the database stayed where it was. f0a91d3c7b62 is an empty merge point that
# rejoins them.

$ErrorActionPreference = "Continue"

function Section($t) {
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor DarkGray
    Write-Host $t -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor DarkGray
}

Section "1. Revision graph - must report exactly one head"
docker compose run --rm backend alembic heads 2>&1 | Select-Object -Last 5

Section "2. Where the database is now"
docker compose run --rm backend alembic current 2>&1 | Select-Object -Last 3

Section "3. Applying migrations"
docker compose run --rm backend alembic upgrade head 2>&1 | Select-Object -Last 25

Section "4. Where the database is after"
docker compose run --rm backend alembic current 2>&1 | Select-Object -Last 3

Section "5. Restarting the services that hold a schema in memory"
docker compose restart backend worker beat
Start-Sleep -Seconds 15
docker compose ps

Section "6. Authorized scope - a scan is refused without one"
# Superuser query: ocg_app is subject to row-level security and returns nothing
# from a session with no organization set, whatever the table contains.
docker compose exec -T postgres psql -U postgres -d omni_cyber_guard -c `
  "SELECT n.name, n.cidr, n.is_authorized_scope, o.name AS organization FROM networks n JOIN organizations o ON o.id = n.organization_id ORDER BY n.created_at DESC LIMIT 20;" 2>&1

Write-Host ""
Write-Host "192.168.1.0/24 must be listed with is_authorized_scope = t." -ForegroundColor Yellow
Write-Host "If it is not, add it in Sites and Networks and mark it authorized." -ForegroundColor Yellow
Write-Host "Scanning a range you have not declared is refused by design, not by accident." -ForegroundColor Yellow
