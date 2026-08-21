# Phases 2–5 — Data Model, Scanner Contract, Vulnerability Intelligence, Exposure Engine

**Status:** complete, verified.
**Verification:** 351 backend tests pass against PostgreSQL 16 · every migration applies, reverses and re-applies cleanly · frontend type-checks, lints and builds with zero warnings (25 routes).

Phase 1 made the platform honest. These four phases give it something real to be honest about: a schema that can express an estate, a scanner contract that admits what it can and cannot run, a live CVE/KEV/EPSS pipeline, and a score that explains itself.

---

## Phase 2 — Data model

**15 new tables.** `sites`, `networks`, `asset_interfaces`, `asset_services`, `asset_software`, `asset_tags`, `asset_tag_links`, `scan_targets`, `credential_profiles`, `exposure_snapshots`, plus the intelligence tables from Phase 4. The schema went from 11 tables to 32.

**Open ports are rows now, not JSON.** They lived in `custom_fields["open_ports"]`, which meant "which hosts expose RDP" could not be answered without loading every asset into Python. Services, software and interfaces are first-class rows with `first_seen`/`last_seen`, which is what makes change detection — "port 3389 appeared on Tuesday", "this service disappeared" — possible at all.

**Findings have a stable identity.** Deduplication was a `title LIKE '%...%'` query: fragile (rewording created a duplicate) and wrong (two ports running the same service collided). Findings now carry a SHA-256 fingerprint derived from asset, class, source, check identifier and location. That makes `first_seen`, `last_seen` and `occurrence_count` meaningful, so "open for 43 days" is a fact rather than an artefact of scan frequency.

The migration reproduces that fingerprint in SQL to backfill existing rows, then collapses the duplicates the old matching let through. A test asserts the SQL and the Python produce byte-identical digests — reimplementing a hash in two languages is exactly the thing that drifts silently.

**Findings say what kind of claim they make.** A new `finding_class` (vulnerability / exposure / misconfiguration / compliance / informational) and `confidence` (confirmed / probable / possible). "Port 3389 is open" and "this host matches CVE-2019-0708" are different assertions with different evidentiary weight; presenting them as one undifferentiated count overstates what a port scan proves. An open port is now recorded as an EXPOSURE, and nmap script results as PROBABLE — NSE frequently decides from a version banner, which can be wrong in both directions.

**Findings close on evidence, not assertion.** When a rescan by the same source no longer sees a finding, it is marked resolved with the scan job that established it. Scoped to one source, because nmap's silence says nothing about what nuclei found; and never overriding an operator's judgment, because a scanner's silence does not overturn a human decision. A resolved finding that reappears is reopened, so a regression cannot hide behind a stale status.

**Credential vault.** Fernet encryption at rest under a key deliberately separate from `SECRET_KEY` — rotating session signing must not render the vault unreadable. There is no plaintext column, no API response field carrying a secret, and one audited code path that decrypts. Every decryption writes an audit record naming the actor, the credential and the target. A wrong key raises rather than returning an empty string, because a silent empty secret surfaces as a confusing permission error against the target host.

**Row-level security — and the trap that makes it useless.** Tenant isolation rested entirely on every developer remembering `.filter(organization_id == ...)`. One omission is a cross-customer leak and nothing catches it. There are now FORCED RLS policies on 20 tables; the session sets its tenant after authentication, and an unscoped connection sees *nothing* rather than everything.

Writing the tests surfaced the real trap: **PostgreSQL exempts superusers from every RLS policy, silently.** The first run passed because the test role was a superuser — policies existed, appeared in `pg_policies`, and enforced nothing. Three consequences:

- `docker-compose` now creates a separate `ocg_app` role with `NOSUPERUSER NOBYPASSRLS` that owns the schema. Your current setup connects as `ocg_user`, which the Postgres image creates as a superuser.
- The API verifies at startup that the policies are genuinely in force, and refuses to start in production if they are not.
- A test asserts the check can actually fail, so it does not pass vacuously.

---

## Phase 3 — Scanner adapter contract

The formal interface from your §13: `validate_configuration` / `validate_target` / `start_scan` / `get_status` / `get_results` / `cancel_scan` / `normalize_results`.

**`start_scan` genuinely starts and returns.** The subprocess base class is built on `Popen` with a reader thread, so the session model is not a pretence layered over a blocking call. Cancellation terminates the real process (SIGTERM, then SIGKILL after 10s) and reports whether it actually stopped something. `get_results` raises if called while a scan is running rather than returning partial results that would read as complete. Tests exercise this against real `sleep` and `sh` processes, not mocks.

**Adapters must be able to say no.** Every adapter probes for its own tool and, when it is missing, returns the command that installs it. A contract test holds every adapter to that: if `available` is false, `remediation` must be non-empty. The Scan Center now renders engines from this report — an engine whose binary is absent is disabled with the reason, instead of being offered and failing.

**Progress is honest.** Most CLI tools do not report a completion percentage, so `percent_complete` is `None` rather than a synthetic bar. The Phase 1 guard against `time.sleep` theatre was sharpened rather than relaxed: sleeping on a *numeric literal* is banned in scanner code (that is how the removed adapters faked progress); sleeping on a named poll interval is allowed.

**Boundary corrections found while writing the contract:**

- **Lynis audits the machine it runs on.** The old adapter accepted a remote IP and then audited the worker, labelling the results with someone else's hostname. It now refuses a remote target and explains why.
- **Nuclei refuses public hosts** at `validate_target`, matching the boundary the rest of the platform enforces.
- **Empty targets are rejected everywhere.** Lynis silently defaulted an empty target to `localhost`, which would audit the worker while the operator believed they had scanned something else.

**Credentialed scanning is wired to the vault.** A scan job references a credential profile; the worker decrypts once, immediately before use, with an audit record naming the scan and target. The Windows adapter runs five read-only PowerShell checks and records the returned value as evidence — and a check that could not run is recorded as *not assessed*, never as passed.

---

## Phase 4 — Vulnerability intelligence

Three live feeds, each split into a fetcher (HTTP, pagination, rate limits) and a parser (a pure function, tested against payloads shaped exactly like the real thing).

| Feed | What it answers |
|---|---|
| **NVD 2.0 API** | What the vulnerability is, and which product versions it affects |
| **CISA KEV** | Whether it is being exploited *right now* |
| **FIRST EPSS** | How likely exploitation is in the next 30 days |

Those are three different questions. CVSS says how bad exploitation would be; prioritising on it alone spends effort on theoretically-severe issues nobody is attacking.

**NVD sync is incremental** — it asks only for records modified since the last success, so a routine refresh is a handful of requests rather than 280,000 CVEs. The first run is bounded by `NVD_INITIAL_SYNC_DAYS` and *says so*, so a partial catalogue is not mistaken for a complete one.

**A failed sync is recorded as failed.** It never leaves a stale success timestamp behind. "Last synced 4 hours ago" and "last *attempted* 4 hours ago and failed" lead to opposite decisions, and a catalogue that quietly stopped updating three months ago looks exactly like one that is current.

**CPE correlation, with the boundaries drawn tight.** Installed software is matched against NVD's published version ranges:

- **Software without a CPE is never matched.** Fuzzy product-name matching would attach CVEs to the wrong software with full confidence.
- **NVD's `vulnerable` flag is honoured.** NVD uses non-vulnerable CPE nodes for context — "affects X *running on* Y". Treating those as vulnerable would blame the platform for a flaw in its tenant.
- **Inclusive and exclusive bounds are kept distinct.** "Fixed in 1.2.3" and "affected through 1.2.3" describe different sets of hosts. The version comparator handles `1.2.10 > 1.2.9`, `8.9p1 < 8.9p2`, and `1.0rc1 < 1.0`.
- **A version-bounded rule never matches an unknown version.** Membership cannot be established, so it is not claimed.
- **Rejected CVEs are not reported.** Raising a record the authority has withdrawn is reporting a retraction.
- **Confidence is PROBABLE, never CONFIRMED.** A version match does not establish that the vulnerable code path is reachable, or that a distribution backport has not already fixed it without changing the version string. The finding text says so.
- **An unscored CVE lands at MEDIUM and says the score is pending** — not at critical (which would flood the queue with unanalysed records) and not at low (which would bury genuinely severe ones NVD has not reached).

Uncorrelatable software is *counted*, not hidden: how much of the estate can be correlated at all is the honest measure of this pipeline's reach.

**Scheduled:** KEV twice daily, EPSS and NVD nightly, then a correlation pass — because a CVE published today can affect software inventoried weeks ago, with nothing about the asset having changed to trigger a rescan.

---

## Phase 5 — Explainable exposure engine

Nine contributors, each computed from real data and each carrying the evidence that produced it: most severe open finding, known-exploited (KEV), exploit probability (EPSS), internet exposure, business criticality, data sensitivity, volume of severe findings, time exposed, exposed high-value services.

```
Exposure 87 · CRITICAL

Known exploited in the wild        +20.0   3 findings reference a CVE in CISA KEV: CVE-2021-44228…
Most severe open finding           +20.0   CRITICAL, CVSS 9.8: Remote code execution in …
Internet facing                    +15.0   Declared internet facing by an operator; never inferred
Exploit probability (EPSS)         +14.3   CVE-2021-44228 has a 95.4% probability of exploitation
Business criticality               +10.0   Classified as critical by an operator
Volume of severe findings           +3.5   7 open critical or high-severity findings
Time exposed                        +2.7   Oldest open finding present for 49 days
Exposed high-value services         +1.5   2 high-value ports open: 445, 3389
──────────────────────────────────────────
TOTAL                              87.0
```

**The contributors always sum to the score.** A breakdown that does not add up is worse than none, so when the total is scaled the components are scaled with it — asserted by test.

**What the model cannot compute is declared, not hidden.** Attack-path position and identity privilege are part of the intended model, but there is no graph and no directory integration yet. Rather than quietly weighting them zero — which makes a partial score look complete — the breakdown lists them as unavailable with what would enable them.

**A zero means "not assessed", and says so.** An asset with no findings and no business context is not scored 0/100 and left to read as clean; `assessed` is false with an explanation. Organization-level scoring averages only assessed assets, because averaging in unscanned ones would dilute the number toward zero and make an unscanned estate look safe.

**Remediation moves the number.** Closed, accepted and false-positive findings stop counting — otherwise fixing something would never change the score. Informational findings never count: recording a fact is not an exposure.

**Weights are configurable per organization,** published via `GET /exposure/model` so the scoring is auditable rather than a black box. A healthcare estate can weight data sensitivity above internet exposure; a public SaaS estate the reverse. There is no universally correct set, and the defaults do not pretend otherwise.

**The trend is a record, not a drawing.** Daily snapshots per organization; days the platform was not running are *absent* from the chart rather than interpolated. Carrying values forward would invent posture for days nothing was observed.

---

## New UI

| Page | What it does |
|---|---|
| **Sites & Networks** | Declare ranges you own. Authorization is a recorded decision with an attributed actor — the Scan Center checks a target against it before offering to scan, so the confirmation has something behind it. |
| **Credentials** | Vault management. Secrets go in and cannot come back out; rotation replaces, it does not reveal. |
| **CVE Intelligence** | The catalogue, the KEV listing, and per-feed sync status — which is what distinguishes "nothing matches your estate" from "never downloaded". |
| **Exposure Overview** | The score, the trend, the most exposed assets, and the full "why this score" breakdown. |
| **Asset detail** | Tabbed: overview, services, software, findings. Classification shows its confidence *and* the signals behind it. Software with no CPE is marked as such, because it cannot be correlated. |
| **Findings** (was Vulnerabilities) | Class and confidence on every row, verbatim evidence in the expanded view, ageing and occurrence count. |

Navigation is restructured into the eight groups from your §5. Modules that do not exist yet are shown disabled and labelled **"Not built"** — visible on the roadmap, impossible to mistake for working.

---

## Things found and fixed along the way

- **`npm ci` failed on a clean checkout** — `@react-three/drei` v10 requires React 19; the project is React 18. Local `node_modules` was masking it.
- **A Redis outage would 500 every rate-limited endpoint**, taking down login. The limiter now falls back to in-process memory and swallows storage errors.
- **The packet monitor could not work in Docker.** It ran in the API container and kept events in a Python deque, while the API serving `/threat-intel` was a different process. Events now go to Redis and the sniffer runs in the worker, which is the container with `CAP_NET_RAW`. The API container's raw-socket capability was removed — it never needed it.
- **Deleting a scan destroyed asset inventory.** `assets.scan_job_id` cascaded on delete, so removing an old scan record deleted the assets whose "last scanned by" pointer happened to reference it — including inventory built over many previous scans. Changed to `SET NULL`. **This is a deliberate behaviour change; flag it if you wanted the old semantics.**
- **`/assets/tags` was unreachable** — it would have been captured by `/assets/{asset_id}` and failed UUID parsing. Route order corrected.
- **Migration enum collisions.** `index=True` on a column makes `create_table` emit an index that collided with an explicitly-named one; `sa.Enum(...)` inside `create_table` emits `CREATE TYPE` a second time. Both caught by running the migrations rather than assuming.

---

## To run this

```bash
cd backend
pip install -r requirements-dev.txt
alembic upgrade head          # 4 new migrations
pytest -v                     # 351 tests

cd ../frontend
npm ci
npm run build
```

**One deployment change matters.** `docker-compose.yml` now creates a non-superuser `ocg_app` role and points the application at it. On an existing volume the init script will not re-run, so either recreate the Postgres volume, or run this once as a superuser:

```sql
CREATE ROLE ocg_app LOGIN PASSWORD 'ocg_password' NOSUPERUSER NOBYPASSRLS;
ALTER SCHEMA public OWNER TO ocg_app;
GRANT ALL ON SCHEMA public TO ocg_app;
```

Then update `DATABASE_URL`. If you skip this, the API will start in development and warn loudly that row-level security is not in force; in production it refuses to start.

**Two optional settings worth setting now:**

- `CREDENTIAL_ENCRYPTION_KEY` — required in production. Without it, credentials are encrypted with a key derived from `SECRET_KEY`, so rotating your JWT secret would render the vault unreadable.
- `NVD_API_KEY` — free from NVD. Raises the request limit from 5 per 30 seconds to 50, which turns the initial catalogue sync from hours into minutes.

And still outstanding from Phase 1: **delete the `_to_delete/` folder** at the repository root.

---

## Where this leaves the roadmap

Done: 1 (truth & foundation) · 2 (data model) · 3 (scanner contract) · 4 (vulnerability intelligence) · 5 (exposure engine).

Next: 6 (remediation workflow — owner, SLA, rescan verification), 7 (configuration & compliance), 8 (identity), 9 (exposure graph), 10 (attack paths), 11 (external attack surface & cloud), 12 (AI agent grounding), 13 (reporting, notifications, search, ticketing), 14 (hardening), 15 (end-to-end acceptance test).

The two factors the exposure engine currently declares unavailable — attack-path position and identity privilege — are Phases 9–10 and Phase 8. When those land, the score stops being partial and the breakdown stops carrying that caveat.
