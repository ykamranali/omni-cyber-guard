# Omni Cyber Guard  -  native scan worker launcher
# Powered by Omni Digital Solution
#
# Runs the Celery worker OUTSIDE Docker, directly on Windows, so nmap can
# see your real LAN (Docker Desktop's network isolation on Windows blocks
# this). Meant to be run by the Scheduled Task that install-autostart.ps1
# sets up  -  but you can also just double-click it any time to start the
# worker manually.
#
# It loops: if the worker crashes for any reason, it's restarted after a
# few seconds rather than silently going down.

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $root "backend"
$venvActivate = Join-Path $backendDir ".venv\Scripts\Activate.ps1"

function Write-Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $msg"
}

Set-Location $backendDir

# --- First-time setup: venv + dependencies ---
if (-not (Test-Path $venvActivate)) {
    Write-Log "No virtual environment found  -  creating one and installing dependencies (first run only, this takes a few minutes)."
    python -m venv .venv
    & $venvActivate
    pip install --upgrade pip | Out-Null
    pip install -r requirements.txt
} else {
    & $venvActivate
}

if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Log "WARNING: nmap was not found on PATH. Network scans will fail until you install it: https://nmap.org/download.html"
}

# --- Point at the Dockerized Postgres/Redis via localhost (they're exposed on the host) ---
$envFile = Join-Path $backendDir ".env"
if (-not (Test-Path $envFile)) {
    Write-Log "ERROR: backend\.env not found. Run .\setup.ps1 from the project root first, so Docker's containers (and this worker's config) exist."
    exit 1
}

Get-Content $envFile | ForEach-Object {
    if ($_ -match "^\s*([^#=]+)=(.*)$") {
        $key = $matches[1].Trim()
        $value = $matches[2].Trim()
        if ($key -ne "DATABASE_URL" -and $key -ne "REDIS_URL") {
            [Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
    }
}
$env:DATABASE_URL = "postgresql://ocg_user:ocg_password@localhost:5432/omni_cyber_guard"
$env:REDIS_URL = "redis://localhost:6379/0"

Write-Log "Starting Celery scan worker (native, real-LAN-capable)..."

# --- Resilient run loop ---
while ($true) {
    try {
        celery -A app.core.celery_app worker --loglevel=info --concurrency=2 --pool=solo
    } catch {
        Write-Log "Worker process error: $_"
    }
    Write-Log "Worker exited  -  this is unexpected while Docker's postgres/redis are running. Restarting in 5 seconds..."
    Start-Sleep -Seconds 5
}
