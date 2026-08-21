# Omni Cyber Guard — Architecture Audit & Implementation Roadmap

**Audit date:** 2026-08-21 · **Commit audited:** `b034c37` (+ 3 uncommitted WebSocket files)
**Scope:** full repository inspection prior to any code modification. No files were changed during this audit.

---

## 1. Current architecture

| Layer | Technology | Assessment |
|---|---|---|
| Frontend | Next.js 14.2 (App Router), React 18, TypeScript, Tailwind 3.4, Zustand, TanStack Query, Recharts, framer-motion, three.js | **Sound.** Keep. Matches the target stack. |
| Backend | FastAPI 0.115, SQLAlchemy 2.0 (sync), Pydantic v2, Alembic | **Sound.** Keep. |
| Database | PostgreSQL 16, 9 Alembic migrations, UUID PKs, `organization_id` on every tenant table | **Sound foundation, schema far too thin.** |
| Queue | Redis 7 + Celery 5.4, one worker container | **Sound.** Keep. |
| Auth | JWT (HS256, python-jose), argon2 password hashing, access + refresh tokens | **Sound.** Hardening needed (see §5). |
| RBAC | 9 roles, 20 permissions, DB-backed `role_permissions` / `user_roles`, `require_permission()` dependency enforced on routes | **Genuinely implemented.** Keep and extend. |
| Graph DB | — | **Missing.** No Neo4j, no graph model. |
| Search | — | **Missing.** |
| Containers | Docker Compose: postgres, redis, backend, worker, frontend | **Working.** Nginx/Traefik, scheduler, scanner services missing. |
| Tests | **Zero.** No pytest, no conftest, no Playwright/Jest. | **Critical gap.** |

**Code volume:** ~4,976 lines backend Python · ~5,778 lines frontend TS/TSX.

### What actually exists

```
backend/app/
  api/v1/endpoints/   19 routers (auth, users, orgs, assets, findings, scans,
                      dashboard, audit_logs, compliance, threat_intel, reports,
                      system, agent, incidents, infrastructure, intelligence,
                      schedules, ws)
  models/             11 models — Organization, User, Role, Permission, Asset,
                      Finding, AuditLog, ComplianceFramework/Control, ScanJob,
                      DashboardSnapshot, ScanSchedule, Incident
  scanners/           base + manager + nmap, nuclei, openvas, zap, lynis, windows_audit
  services/           network_scanner, risk_scoring, threat_monitor, llm, audit,
                      bootstrap, org_provisioning, notifications, snapshots, websocket
  tasks/              scan_tasks (Celery), scheduler_tasks
frontend/app/(dashboard)/   17 pages
```

---

## 2. Feature status — the honest ledger

### ✅ WORKING (real backend, real data, real persistence)

| Feature | Evidence |
|---|---|
| **Nmap discovery + service/OS scan** | `services/network_scanner.py` — real `nmap -A --script vuln,default -F` subprocess, real XML parsing, real ARP-table MAC correlation, streamed progress. This is genuine. |
| **Scan → asset → finding pipeline** | `tasks/scan_tasks.py` — creates/updates `Asset` rows and `Finding` rows from parsed nmap output only. |
| **Nuclei integration** | `scanners/nuclei.py` — real subprocess, real JSON parsing, honest `is_available()` via `shutil.which`. |
| **Lynis integration** | `scanners/lynis.py` — real subprocess + real `.dat` report parsing. (Local-host audit only; the remote/SSH path is a comment, not code.) |
| **Windows credentialed audit** | `scanners/windows_audit.py` — real WinRM/PowerShell checks (Defender, SMBv1, RDP NLA). Correctly reports unavailable if `pywinrm` is absent. |
| **Scan authorization guardrail** | `validate_authorized_target()` — rejects public ranges and >/22 targets *before any packet is sent*. Good, and rare to see done properly. |
| **Dashboard KPIs** | `endpoints/dashboard.py` — every number is a real `COUNT`/`AVG` query. `/trend` returns only recorded snapshots, no interpolation. **Compliant with your no-mock rule.** |
| **RBAC enforcement** | `core/deps.py::require_permission` on routes; frontend hiding is cosmetic only. |
| **Tenant isolation (query level)** | Every org-scoped query filters `organization_id == current_user.organization_id`. |
| **Audit logging** | `services/audit.py` + `AuditLog` model; wired into login, scans, org/user changes. |
| **Risk scoring** | `services/risk_scoring.py` — deterministic, derived from real linked findings. Simplistic but honest. |
| **Live packet threat monitor** | `services/threat_monitor.py` — real Scapy sniffer detecting SYN-scan patterns and cleartext credentials. |
| **PDF reporting** | `reports/pdf_generator.py` — real ReportLab output. |
| **Scheduled scans** | `ScanSchedule` model + `tasks/scheduler_tasks.py` with croniter. |

### 🔴 MOCK / FABRICATED — direct violations of your §3 and §52 rules

| File | Violation | Severity |
|---|---|---|
| **`scanners/openvas.py`** | Entirely fabricated. `is_available()` hardcoded `True`; `time.sleep()` fake progress theatre ("Loaded 140,293 active vulnerability signatures"); returns 3 **hardcoded CVE findings** (CVE-2024-21412, CVE-2024-3094, SMBv1) written to the database as if real, with invented evidence strings. **No GVM/OpenVAS API call exists anywhere.** | 🔴 **CRITICAL** |
| **`scanners/zap.py`** | Identical pattern. Fake spider/active-scan logs, then 3 hardcoded findings claiming *"Successfully injected SQL payload"* and *"Payload `' OR '1'='1` successfully bypassed the query logic"*. **This asserts exploitation that never occurred** — violates your §20 and §66 rules outright. **No ZAP daemon/API integration exists.** | 🔴 **CRITICAL** |
| **`endpoints/threat_intel.py`** | `MOCK_THREATS` — 6 hardcoded CVEs with synthetic `published_at` timestamps generated from `now() - timedelta(days=N)`. Surfaced as `global_cves` and `zero_days_tracked` on the Threat Intelligence page. | 🔴 **HIGH** |
| **`components/dashboard/activity-ticker.tsx`** | `MOCK_SYSTEM_EVENTS` injected at random intervals into the live activity feed. | 🟠 **MEDIUM** |
| **`endpoints/intelligence.py`** | Two of four "insights" are hardcoded heuristics with invented `confidence_score` values (85, 95, 98, 100). The FTP recommendation is a canned string. | 🟠 **MEDIUM** |
| **`services/notifications.py`** | Email + in-app notification senders are stubs that log and return. Callers believe delivery succeeded. | 🟠 **MEDIUM** |
| **`scanners/nmap.py`** | `RISKY_PORTS` findings are honest *hygiene heuristics*, but are stored as `Finding` rows indistinguishable from CVE-backed vulnerabilities. Needs a `finding_class` discriminator. | 🟡 **LOW** |

### 🐛 BROKEN

| Issue | Location | Impact |
|---|---|---|
| `AttributeError: 'Finding' object has no attribute 'evidence'` | `agents/security_engineer.py:52` reads `finding.evidence`; the `Finding` model has no `evidence` column. | **"Analyze finding" AI action crashes on every call.** |
| Progress-callback session storm | `tasks/scan_tasks.py::log_progress` opens a **new `SessionLocal()` per output line** and appends to a `Text` column. On a verbose nmap run this is thousands of sessions and an unbounded-growth column. | Worker exhausts the connection pool on large scans. |
| Blocked-IP state is in-memory | `endpoints/infrastructure.py::blocked_ip_metadata` (module-level dict) + `threat_monitor.blocked_ips` (module-level set). | **Lost on every restart. Not shared between API and worker containers — so a block made via the API never reaches the sniffer in the worker.** The feature does not actually work in Docker. |
| Scan cancel is a lie | `endpoints/scans.py::cancel_scan` sets `status=FAILED`; the running nmap subprocess is never killed. `error_message` reads "Scan manually canceled" while the scan continues. | Violates §53. |
| `BackgroundTasks` + `asyncio.run()` for WebSocket | `endpoints/scans.py` | Broadcasts only reach clients connected to *that* API process. |
| 11 hardcoded `http://localhost:8000` URLs | 7 frontend files bypass `lib/api.ts` | Breaks any non-localhost deployment; also bypasses 401 handling. |
| Nuclei findings never get `scan_job_id` | `tasks/scan_tasks.py` nuclei block | Findings orphaned from their scan. |

### ⚠️ SECURITY GAPS

1. **TCP RST injection** (`threat_monitor.py::process_packet`) forges packets with a **spoofed source IP** to tear down connections. This is an active-disruption capability that spoofs traffic, is trivially abused as a denial-of-service against arbitrary hosts on the segment, and is inconsistent with the defensive-only posture the codebase claims in its own docstrings. **Recommend removal**, replaced with alert + host-firewall-rule recommendation (or an authenticated, audited integration with a real firewall API).
2. **`RATE_LIMIT_PER_MINUTE` is configured but never enforced** — `slowapi` is in `requirements.txt` and never imported. Login has **no rate limit and no lockout** → unlimited credential-stuffing.
3. **No credential vault.** §33 is entirely unimplemented. `windows_audit.py` takes plaintext `username`/`password` kwargs; there is no `credentials` table, no encryption at rest, no rotation, no access audit.
4. **MFA is schema-only.** `mfa_enabled`/`mfa_secret` columns exist; `pyotp` is installed; **no verification code path exists.** Login ignores MFA entirely.
5. **No refresh-token revocation.** Tokens are stateless with no JTI, no denylist, no logout invalidation. A stolen refresh token is valid for 7 days.
6. **Default secrets shipped in `.env.example`** and as config defaults (`insecure-dev-secret-change-me`, `ChangeMe!12345`). There is no startup assertion that these were changed in production.
7. **No `tenant_id` DB-level enforcement.** Isolation depends entirely on every developer remembering the `.filter()`. One omission leaks cross-tenant data. Postgres RLS is the fix.
8. **CSP is `default-src 'self'`** while Next.js requires inline styles/scripts — likely already violated in the browser console; needs a real nonce-based policy.
9. **`docker-compose` grants `NET_RAW`/`NET_ADMIN` to the *backend* API container**, not just the worker. The API has no need for raw sockets.

### 🧱 TECHNICAL DEBT

- `scan_tasks.py::run_network_scan` is a 312-line monolith mixing orchestration, asset upsert, finding creation, dedup, nuclei fan-out and risk recompute. Untestable as written.
- `except (RuntimeError, Exception)` and bare `except Exception: pass` swallow real errors in ~8 places.
- `@app.on_event("startup")` is deprecated in modern FastAPI; use lifespan.
- Sync SQLAlchemy under async FastAPI — every DB call blocks an event-loop thread.
- No pagination on `/assets`, `/findings` — §43 violation waiting to happen at 10k assets.
- `Asset.custom_fields` JSON blob holds `open_ports` — unqueryable, unindexable. Needs `asset_services` table.
- `ScanType` enum has only 2 values; the UI offers 4 engines.
- No `/api/health` deep checks (DB, Redis, worker liveness).

---

## 3. Missing modules (vs. your target spec)

| # | Module | Status |
|---|---|---|
| 15 | CVE intelligence pipeline (NVD sync, CPE matching) | **Absent** — no `cves`, `cwes`, `cpes` tables |
| 15 | EPSS scores | **Absent** |
| 15 | CISA KEV | **Absent** |
| 17 | Explainable exposure score with contributor breakdown | **Absent** — current score is severity-count only |
| 18 | Asset criticality / business context | **Absent** |
| 19 | Exposure graph (Neo4j) | **Absent** |
| 20 | Attack path analysis + POTENTIAL/VERIFIED distinction | **Absent** |
| 21 | Identity security (AD/LDAP) | **Absent** |
| 22 | Cloud security (AWS/Azure/GCP) | **Absent** |
| 23 | Configuration assessment (CIS/NIST checks) | **Partial** — Lynis + Windows audit exist, no framework mapping |
| 24 | Compliance engine (Framework→Control→Check→Evidence→Result) | **Fake** — `coverage_percent` is a manually-typed number, not derived from assessment |
| 26 | External attack surface management | **Absent** |
| 28 | Remediation engine (SLA, owner, verification workflow) | **Absent** — only a `status` enum |
| 29 | Ticketing (Jira/ServiceNow/webhook) | **Absent** |
| 33 | Credential vault | **Absent** |
| 39 | Global search | **Absent** |
| 40 | Notification engine | **Stub** |
| 49 | Tests (unit / integration / E2E) | **Absent** |
| 55 | Finding deduplication (`first_seen`/`last_seen`/`occurrence_count`) | **Absent** — dedup is a fragile `title LIKE` match |
| 56 | Remediation verification (rescan → auto-resolve) | **Absent** |

**Data model gap:** the spec calls for ~45 tables. **11 exist.**

---

## 4. Verdict: CURRENT → KEEP / IMPROVE / REPLACE / ADD

### KEEP unchanged
Next.js + FastAPI + Postgres + Celery/Redis stack · RBAC model and `require_permission` · JWT/argon2 auth core · Alembic setup · `network_scanner.py` nmap engine and its authorization guardrail · `dashboard.py` (already no-mock compliant) · audit-log service · the entire visual design language and component library.

### IMPROVE
`Asset` model (→ `asset_services`, `asset_software`, `asset_interfaces`, criticality, tags) · `Finding` model (→ dedup identity, `first_seen`/`last_seen`, `occurrence_count`, `evidence`, `finding_class`) · `ScanJob` (→ `scan_targets`, `scan_jobs`, per-target status, real cancel) · `risk_scoring.py` (→ explainable contributor model) · `scan_tasks.py` (→ decompose into normalizer/correlator/persister) · `scanners/base.py` (→ full `ScannerAdapter` contract per §13) · frontend `lib/api.ts` adoption everywhere.

### REPLACE
`scanners/openvas.py` → real GVM/`python-gvm` GMP adapter, or **"Integration not configured"** · `scanners/zap.py` → real ZAP daemon API adapter, or **"Integration not configured"** · `endpoints/threat_intel.py` `MOCK_THREATS` → real NVD/KEV/EPSS tables · `activity-ticker.tsx` mock events → real event stream · `threat_monitor.py` RST injection → alert-only + firewall recommendation · in-memory blocked-IP store → DB table · `compliance` coverage slider → evidence-derived results.

### ADD
Everything in §3 above, plus: credential vault, Postgres RLS, rate limiting, MFA verification, pagination, Neo4j service, scheduler container, Nginx/Traefik, `.env` production assertions, and a full test suite with a local vulnerable-target lab (OWASP Juice Shop container).

---

## 5. Implementation roadmap

Ordering is driven by **dependency**, not by your §58 numbering — the risk engine cannot be built before CVE intelligence exists, and nothing can be verified before tests exist.

### Phase 1 — Truth & Foundation *(no new features; make the app honest)*
> **Rationale:** you cannot build a real platform on top of a scanner that fabricates CVEs. This phase is the prerequisite for every phase after it.

| Action | Files |
|---|---|
| Delete fabricated findings from `openvas.py` / `zap.py`; replace with real adapters gated by `is_available()` that return "Integration not configured" | `backend/app/scanners/openvas.py`, `zap.py`, `base.py` |
| Add DB migration to purge any findings with `source in ('openvas','zap')` created by the fake adapters | `backend/alembic/versions/` |
| Replace `MOCK_THREATS` and `MOCK_SYSTEM_EVENTS` with empty-state UI | `endpoints/threat_intel.py`, `activity-ticker.tsx` |
| Fix `finding.evidence` crash — add `evidence` column + migration | `models/finding.py`, `agents/security_engineer.py` |
| Fix `log_progress` session storm — batch writes, cap `raw_summary` | `tasks/scan_tasks.py` |
| Make scan cancel real — store worker PID / use Celery revoke + subprocess kill | `tasks/scan_tasks.py`, `endpoints/scans.py` |
| Move blocked IPs to a DB table; remove RST injection | `models/`, `endpoints/infrastructure.py`, `services/threat_monitor.py` |
| Route all frontend calls through `lib/api.ts` | 7 frontend files |
| Enforce `slowapi` rate limiting + login lockout | `main.py`, `endpoints/auth.py` |
| **Stand up pytest + a `docker-compose.test.yml` with Postgres and OWASP Juice Shop** | `backend/tests/` (new) |

**Exit criterion:** `pytest` green; a scan against the Juice Shop container produces findings that are all traceable to real scanner output; no string matching `mock|fake|simulated` remains in `backend/app/scanners` or `endpoints`.

### Phase 2 — Data model expansion
`asset_interfaces`, `asset_services`, `asset_software`, `asset_tags`, `asset_criticality`, `sites`, `networks`, `scan_targets`, `scan_jobs`, `credentials`/`credential_profiles` (encrypted), `finding` dedup identity. Postgres RLS for tenant isolation. Full Alembic migration chain.

### Phase 3 — Scanner adapter contract + real integrations
Formal `ScannerAdapter` per §13 (`validate_configuration` / `start_scan` / `get_status` / `get_results` / `cancel_scan` / `normalize_results`). Real GVM adapter (`python-gvm`). Real ZAP adapter (`zaproxy` API). Masscan/httpx/testssl adapters.

### Phase 4 — Vulnerability intelligence pipeline
`cves`, `cwes`, `cpes`, `epss_scores`, `kev_entries` tables. Incremental NVD 2.0 API sync, CISA KEV JSON feed, FIRST EPSS CSV — all scheduled, cached, timestamped. CPE-based correlation from `asset_software` → CVE.

### Phase 5 — Explainable risk & exposure engine
Configurable weighted model producing a stored contributor breakdown per §17/§38. Asset criticality applied. Exposure trend snapshots.

### Phase 6 — Remediation engine
Owner, due date, SLA, `OPEN→ASSIGNED→IN_PROGRESS→FIXED→RESCAN→VERIFIED→CLOSED`, risk acceptance with approver + expiry, **rescan-driven auto-verification** (§56).

### Phase 7 — Configuration & compliance
`Framework→Requirement→Control→Check→Evidence→Result`. CIS/NIST content packs. Compliance results derived *only* from real check outcomes.

### Phase 8 — Identity exposure
LDAP/AD read-only collection, privileged-group and stale-account analysis.

### Phase 9 — Exposure graph (Neo4j)
Node/edge model per §19, projected from real Postgres data.

### Phase 10 — Attack path analysis
Path enumeration over the graph with mandatory `POTENTIAL` / `VERIFIED` / `OBSERVED` labelling and per-step evidence.

### Phase 11 — External attack surface + cloud
Domain/subdomain/cert discovery with ownership proof; AWS/Azure/GCP read-only assessment.

### Phase 12 — AI agent grounding
Replace free-text prompting with a tool-calling agent over typed DB query functions; enforce "insufficient evidence" refusals; confirmation gates on all write actions (§37).

### Phase 13 — Reporting, notifications, search, ticketing
### Phase 14 — Hardening: MFA, credential vault, token revocation, RLS verification, Nginx/Traefik, secrets management
### Phase 15 — Full E2E acceptance test (§61) as automated CI

---

## 6. Execution constraints you need to decide on

The repository lives on your Windows machine at `D:\Kamran Projects\omni-cyber-guard`. I can read and write those files directly. Two things I **cannot** do from here:

1. **Run your stack.** The bridge to your machine has no network access and a 45-second command budget — it cannot run `docker compose up`, `alembic upgrade`, `pytest`, or `npm run build`. I can write code and tests; **you** run them and paste failures back, or we iterate through your terminal.
2. **Install packages on your machine.** Same restriction.

This matters because your §60 "Definition of Done" requires tests to pass. My proposal: I write code *and* its tests together, you run one command per phase, and we close the loop on failures. That keeps the "no unverified completion" rule intact rather than me declaring things done blind.

---

*Prepared as STEP 1–3 of the Omni Cyber Guard production engineering mandate. No source files were modified during this audit.*
