# Phase 1 — Truth & Foundation

**Status:** complete, verified.
**Verification:** 81 backend tests pass against PostgreSQL 16; the Alembic chain applies, reverses and re-applies cleanly; the frontend type-checks, lints and builds with zero warnings.

Phase 1 changed no product surface that was working. It removed everything that reported security results the platform had not actually produced, fixed the places where the UI claimed an outcome that had not happened, and put a test suite and CI pipeline behind the rules so none of it comes back silently.

---

## 1. Fabricated security data — removed

| What | Where it was | What happened |
|---|---|---|
| **OpenVAS engine** | `backend/app/scanners/openvas.py` | Removed. It contained no GVM integration. `is_available()` returned a hardcoded `True`, progress was `time.sleep()` printing invented lines ("Loaded 140,293 active vulnerability signatures"), and it returned three hardcoded findings — CVE-2024-21412, CVE-2024-3094, SMBv1 — with invented evidence, written to the database and counted on the dashboard. |
| **ZAP engine** | `backend/app/scanners/zap.py` | Removed. Same pattern, and worse: it asserted exploitation that never occurred, with the evidence string *"Payload `' OR '1'='1` successfully bypassed the query logic on the target endpoint."* No ZAP daemon or API client existed anywhere in the codebase. |
| **6 hardcoded CVEs** | `endpoints/threat_intel.py::MOCK_THREATS` | Removed. Timestamps were manufactured with `now() - timedelta(days=N)`. The Threat Intelligence page now shows an explicit "awaiting first synchronisation" state naming the feeds that are not yet configured. |
| **Rotating fake activity feed** | `components/dashboard/activity-ticker.tsx::MOCK_SYSTEM_EVENTS` | Removed. It injected an invented event every 4.5 seconds so the panel always looked busy. A quiet network now reads as quiet, and an offline monitor says so explicitly. |
| **Invented confidence scores** | `endpoints/intelligence.py` | Removed. Insights carried `confidence_score` values of 85 / 95 / 98 / 100 that were never computed, plus a canned FTP recommendation returned whether or not it applied, plus an "All clear — posture is optimal" entry emitted whenever nothing correlated. Insights now carry an `evidence` object naming the exact finding and event IDs behind them, and an empty result renders as "nothing to correlate", not as reassurance. |
| **Fake seed assets and findings** | `app/scripts/seed.py` | Removed. It generated random IPs and randomly-assigned CVE findings. The script now creates accounts and roles only — no security data. |
| **Data purge** | migration `a1f0c3d29b74` | Deletes every finding with `source in ('openvas','zap')`, removes the placeholder assets those runs invented, detaches real records from fabricated scan jobs, then deletes the jobs. |

## 2. Outcomes the platform claimed but had not achieved

**Scan cancellation was fiction.** `POST /scans/{id}/cancel` wrote `status = FAILED` with the message "Scan manually canceled by user" while the nmap process ran to completion. Now: the endpoint sets `cancel_requested`; the worker polls it every 3 seconds and calls `terminate()`, escalating to `kill()` after 10 seconds. A new `CANCELED` status distinguishes a cancellation from a failure. A queued job that never started is cancelled immediately.

**Settings saves reported success unconditionally.** The handler `await`ed `fetch()` without inspecting the response, so a 403 or a 500 still rendered "Saved successfully!". Failures now surface the actual error.

**CSV asset export could never have worked.** It used `window.location.href`, which sends no `Authorization` header, so every click hit the API unauthenticated. Now routed through an authenticated blob download.

**Notification delivery was assumed.** `send_email` and `send_in_app_notification` logged a line and returned `None`; callers had no way to know nothing was sent. Both now return a `NotificationResult` reporting `delivered=False` with the reason. The webhook channel — which is real — reports its actual HTTP outcome.

**"Export mitigation scripts" buttons did nothing.** They now generate real `iptables` and `New-NetFirewallRule` scripts from the live blocklist.

## 3. Active-defense packet forging — removed

`threat_monitor.py` forged TCP RST packets **with a spoofed source address** to tear down connections from blocklisted IPs. Removed. Forging packets with an address you do not own is indistinguishable from an attack, can be aimed at any host on the segment, and cannot be reconciled with the defensive-only posture the codebase asserts in its own docstrings. Detection and alerting are unchanged.

The blocklist itself was also broken in a way that was invisible from the UI: it lived in a module-level Python `set` and a module-level `dict`. It was lost on every restart, and because the API and the worker are separate containers, a block created through the API never reached the sniffer that was supposed to act on it. **In Docker, the feature did nothing at all.** It is now a `blocked_ips` table with an organization scope, a status (`recommended` / `enforced` / `expired`), an audit trail, and a banner stating plainly that Omni Cyber Guard records the decision and does not interrupt traffic.

## 4. Correctness and stability

- **Connection-pool exhaustion.** `log_progress` opened a new `SessionLocal()` for *every line* of nmap output and appended it to an unbounded `TEXT` column — thousands of sessions on a verbose scan. Replaced with `ScanProgressReporter`, which buffers and flushes every 2 seconds or 40 lines, with a 200 KB cap on stored output.
- **`AttributeError` on every AI analysis.** `agents/security_engineer.py` read `finding.evidence`; the column did not exist. Added as a first-class column, and now populated with verbatim scanner output — banner text, script output, matched URLs — kept separate from the narrative description.
- **`scan_tasks.py` decomposed** from a 312-line monolith into named, individually testable functions.
- **Silent failures surfaced.** A nuclei run that crashed was swallowed by `except Exception: pass`, so an unassessed service was indistinguishable from a clean one. Failures now produce an explicit "assessment failed — this service has not been assessed" finding.
- **Unknown severities no longer default to critical.** They map to `info`.
- **Unknown scan engines** are rejected at the API boundary instead of failing later inside a Celery worker.

## 5. Security hardening

- **Login had no rate limit and no lockout.** `slowapi` was a declared dependency and `RATE_LIMIT_PER_MINUTE` a config value; neither was referenced anywhere. Now wired up: 120 req/min globally, 10 req/min on credential endpoints, and a per-account lockout after 5 failures for 15 minutes.
- **Rate limiting fails open, not closed.** With the default configuration a Redis outage would make every rate-limited request raise `ConnectionError` and return 500 — taking down login for everyone. The limiter falls back to in-process memory and swallows storage errors, degrading the limit from cluster-wide to per-replica.
- **Login no longer confirms which accounts exist.** A miss hashes a dummy password so the timing resembles a hit, and both paths return an identical message.
- **Production refuses to start on shipped default secrets.** `assert_production_ready()` raises if `SECRET_KEY` or `FIRST_SUPERADMIN_PASSWORD` still hold their `.env.example` values while `ENVIRONMENT=production`.
- **CSP corrected.** The blanket `default-src 'self'` broke the Swagger docs UI while being too loose to protect the app. Replaced with `default-src 'none'` on API responses, an exemption for the docs routes, and HSTS only in production.
- **11 hardcoded `http://localhost:8000` URLs** across 7 files now route through `lib/api.ts`, which handles auth and 401 expiry. The WebSocket URL is derived from the configured API base rather than hardcoded.

## 6. Tests and CI — new

`backend/tests/` — **81 tests, all passing** against PostgreSQL 16.

| File | Covers |
|---|---|
| `test_no_fabricated_data.py` | AST-based guard: fails the build if fabricated-data containers, `time.sleep` scan theatre, the removed scanner modules, or literal dashboard metrics reappear. Strips docstrings and comments first, so explaining a past mistake does not trip it. |
| `test_scan_authorization.py` | The safety guardrail: public ranges, malformed input, IPv6 and oversized CIDRs all rejected before a packet is sent. |
| `test_nmap_parsing.py` | Real nmap XML → hosts, ports, banners, scripts. Down hosts and closed ports excluded; nothing invented. |
| `test_scan_pipeline.py` | Scanner output → asset → finding. Upsert not duplicate, evidence populated, severity mapping, dedup on rescan. |
| `test_risk_scoring.py` | Determinism, monotonic weights, capping, remediated findings excluded. |
| `test_auth_and_rbac.py` | Argon2 hashing, token type confusion, and the RBAC matrix enforced against real users. |
| `test_login_lockout.py` | Counter, lockout, expiry, reset, and identical responses for unknown vs. wrong password. |
| `test_tenant_isolation.py` | One organization cannot list or fetch another's assets or scans. |
| `test_scan_request_validation.py` | Engine allow-list; the removed engines stay removed. |

`.github/workflows/ci.yml` runs three jobs on every push and PR: **backend** (Postgres + Redis services, `alembic upgrade head`, a downgrade/upgrade round-trip to prove reversibility, then pytest with coverage), **frontend** (`npm ci`, `tsc --noEmit`, lint, build), and a deliberately separate **no-fabricated-data** job so a red build for that reason is unmistakable.

## 7. Dependency fix found during verification

`npm ci` failed outright on a clean checkout: `@react-three/drei@^10` and `@react-three/fiber@^9` both require React 19, while the project is on React 18 with Next 14. Local development worked only because `node_modules` had been installed before the constraint tightened. Pinned to `drei@^9.114.3` / `fiber@^8.17.10` / `three@^0.169.0`, which support React 18. Verified: install, type-check, lint and production build all clean.

---

## Action required from you

**Delete the `_to_delete/` folder** at the repository root, then commit. The tooling that removed those files cannot delete on this machine, so it moved them there instead. The folder contains the two fabricated scanner modules and two temporary build archives, with a README explaining each.

**Then run:**

```bash
cd backend
pip install -r requirements-dev.txt
alembic upgrade head        # applies the Phase 1 migration and purges fabricated findings
pytest -v                   # needs Postgres: docker compose up -d postgres

cd ../frontend
npm ci                      # picks up the corrected lockfile
npm run build
```

Push to `master`, `main`, or any `phase-*` branch and CI will run all of it automatically.

---

## What Phase 1 did not do

No new capability was added. The scanner adapter contract, the CVE/EPSS/KEV intelligence pipeline, the explainable exposure score, the exposure graph, attack paths, identity, cloud, the credential vault, and the remediation workflow all remain unbuilt — they are Phases 2 through 15 in `ARCHITECTURE_AUDIT.md`. Phase 1's job was to make sure that what the platform already claimed was true, and to make it expensive to break that again.
