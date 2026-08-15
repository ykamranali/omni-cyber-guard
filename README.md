# Omni Cyber Guard

Enterprise Cybersecurity & Vulnerability Management Platform — Powered by Omni Digital Solution.

This repository contains **Milestone 2** of the platform: a working, real-data web application — authentication, RBAC, multi-tenant data model, a live dashboard, full asset management, real network scanning, vulnerability management, user management, and organization administration. Every widget and page is wired to genuinely computed data from your own database — nothing is hardcoded or fabricated. The application ships **empty**: no demo organization, no demo assets, no demo findings. The only thing created automatically is one super administrator account, so you have a way to log in.

## What's real vs. what's deferred

Everything shipped here is functional against real data:

- **Authentication & RBAC** — JWT auth, 9 platform roles, granular database-backed permissions, multi-tenant isolation.
- **Asset inventory** — manual entry, CSV import/export, search/filter.
- **Real network scanning** — an actual `nmap`-backed host discovery + port/service scan, restricted to private (RFC1918) or loopback ranges you specify. Discovered hosts become real Asset records; risky exposed services (Telnet, RDP, exposed databases, etc.) become real Finding records with generic, non-fabricated remediation guidance. No CVE IDs or CVSS scores are invented — those only appear on findings you enter manually with real values.
- **Vulnerability management (Findings)** — full list/filter/status-update UI, backed by the real findings table.
- **Asset risk scoring** — computed live from each asset's actual open findings (severity-weighted), not random or hardcoded.
- **Dashboard** — every widget pulls from real queries: security/risk score, findings by severity, asset health, remediation progress, compliance framework coverage (starts at a real 0% until you update it), a 7-day risk trend built from daily snapshots the app records automatically as you use it, recent scan jobs, and top-risky-assets ranked by real computed risk score.
- **Geographic Asset Distribution** — plots assets that have a recorded latitude/longitude. This intentionally replaces the "live attack map" style widget you may have seen in reference dashboards: we have no real threat-intelligence feed behind that kind of widget in this milestone, and showing fabricated attack markers would misrepresent invented data as real telemetry.
- **System Status** — actually probes the database, Redis, and the nmap scan engine rather than showing a hardcoded "operational" string.
- **User management** — create/deactivate users, assign roles, all real API calls.
- **Organization administration** — branding settings for your org; platform super admins can create and list additional organizations (each gets its own real roles, permissions, and compliance framework rows).
- **Theme toggle** — a real dark/light theme switch, persisted per-browser.

Still marked "Soon" in the sidebar (not built this round, so as not to ship half-finished pages): Compliance dashboard UI (the backend API exists — `/api/v1/compliance/frameworks` — just no dedicated page yet), Reports, Threat Intelligence, Settings (beyond branding), Audit Logs UI, Licensing.

## Quickstart (Windows)

From inside this folder, in PowerShell:

```powershell
.\setup.ps1
```

This asks for the email/password you want to log in with, generates a secret key, starts every container, waits for the backend to come up, and runs migrations — one command instead of the five below. Safe to re-run (it won't duplicate migrations or overwrite an admin account you already set). See "Running the scan worker natively" further down if you want to scan your real LAN rather than just the Docker network.

## Always-on setup: start automatically every time you log in to Windows

By default you have to run `docker compose up` and start the worker by hand each time. To make the whole app (frontend, backend, and the real-LAN scan worker) come up automatically on every boot with no manual steps:

```powershell
.\setup.ps1                          # run once, if you haven't already
.\scripts\install-autostart.ps1      # run once — sets up auto-start
```

What this does, permanently, until you undo it:

- Flips Docker Desktop's own "Start Docker Desktop when you log in" setting on. Since every service in `docker-compose.yml` already has `restart: unless-stopped`, Docker bringing itself back up is enough to bring postgres, redis, the backend API, and the frontend back up with it — you don't need to run `docker compose up` again.
- Registers a Windows Scheduled Task (`OmniCyberGuard-ScanWorker`, visible in Task Scheduler) that starts the scan worker **natively** at logon — not in Docker, because Docker Desktop on Windows can't see your physical LAN. This is the piece that makes network scans actually find your real devices. If it crashes for any reason, both the task itself (via its restart policy) and an internal retry loop in the script bring it back.

After running this once: reboot, log in, wait about 30-60 seconds, then http://localhost:3000 is up and scans will reach your real network — no terminal needed.

To undo it: `.\scripts\uninstall-autostart.ps1` (removes the scheduled task; leaves Docker/your data alone).

**Note:** the first time the scan worker starts this way, it has to create a Python virtual environment and install dependencies, which takes a few minutes and needs internet access. After that first run it starts in seconds. If `nmap` isn't installed yet, the worker will still start but scans will fail until you install it: https://nmap.org/download.html

## Authorized-use requirement for network scanning

The network scan feature is real reconnaissance tooling (`nmap`), not a simulation. It is hard-restricted in code (`backend/app/services/network_scanner.py`) to private/loopback IP ranges only — it will refuse to scan any public IP range. **Only run it against networks you own or are explicitly authorized to assess.** It performs host/port/service discovery only: no exploit execution, no credential attacks, no payload delivery, anywhere in this codebase.

### Important: scanning your real LAN vs. the Docker network

By default, the scan worker container only sees Docker's internal bridge network, not your physical Wi-Fi/Ethernet LAN. To scan your actual home/office network (e.g. `192.168.1.0/24`):

- **Linux:** uncomment `network_mode: host` under the `worker` service in `docker-compose.yml`.
- **Windows/Mac (Docker Desktop):** host networking isn't reliably supported. Run the worker natively instead — see "Running the scan worker natively" below.

## Running it locally

**Prerequisites:** Docker and Docker Compose. This was built and logic-tested in a sandbox with no Docker/network access, so full end-to-end container build hasn't been run — review before trusting it in a sensitive environment.

```bash
cd omni-cyber-guard
cp backend/.env.example backend/.env      # set SECRET_KEY and FIRST_SUPERADMIN_* before any real use
cp frontend/.env.local.example frontend/.env.local

docker compose up --build
```

Then run migrations (the app does NOT auto-create tables — Alembic is the source of truth):

```bash
docker compose exec backend alembic revision --autogenerate -m "initial schema"
docker compose exec backend alembic upgrade head
```

That's it — no seeding required. On first startup the API automatically creates exactly one super administrator account from `FIRST_SUPERADMIN_EMAIL` / `FIRST_SUPERADMIN_PASSWORD` in `backend/.env` (defaults: `admin@omnidigitalsolution.com` / `ChangeMe!12345` — change these in `.env` before running for real).

- Frontend: http://localhost:3000
- Backend API docs: http://localhost:8000/api/docs

Log in with your super admin account, then use **Organizations → New Organization** to create your real organization (with its own admin user), or just start adding assets directly under the bootstrap "Platform Administration" org.

### Optional demo data

If you want sample data to explore the UI with before adding your own, run:

```bash
docker compose exec backend python -m app.scripts.seed
```

This is skipped automatically if any data already exists, and every seeded asset is tagged `demo-data` so it's clearly distinguishable from anything real you add.

### Running the scan worker natively (Windows/Mac, to scan your real LAN)

On Windows, the easiest path is `.\scripts\install-autostart.ps1` (see above) — it does this for you and keeps it running across reboots. To run it manually just once instead:

```powershell
.\scripts\start-scan-worker.ps1
```

Or, doing it by hand on any OS:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
# install nmap for your OS: https://nmap.org/download.html
celery -A app.core.celery_app worker --loglevel=info --pool=solo   # --pool=solo is required on Windows
```

Point `DATABASE_URL` / `REDIS_URL` in your local `.env` at the Dockerized Postgres/Redis (`localhost:5432` / `localhost:6379`, both are exposed by docker-compose).

## Running without Docker entirely

**Backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# requires a running Postgres + Redis matching backend/.env, and `nmap` installed for scanning
alembic upgrade head
uvicorn app.main:app --reload
```
In a second terminal: `celery -A app.core.celery_app worker --loglevel=info` (required for scans to actually run — the API only enqueues them).

**Frontend**
```bash
cd frontend
npm install
npm run dev
```

## Security notes

This platform is designed exclusively for defensive security and authorized assessments. It does not include, and will never include, exploit execution, malware delivery, credential attack tooling, persistence mechanisms, or privilege-escalation capability. Vulnerability findings come only from authorized scan results or manual entry with real values.

## Suggested next milestone

A dedicated Compliance page (backend already supports it), Reports/export engine, and Threat Intelligence (which would need a real external feed integrated — worth discussing which one before building, so nothing in it ends up fabricated either).

---
Powered by Omni Digital Solution
