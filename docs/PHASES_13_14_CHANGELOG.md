# Phases 13–14 — Repository-wide truth pass, and the firewall integration

**Status:** complete, verified.
**Verification:** 581 backend tests pass against PostgreSQL 16 (was 411 before this session); the full Alembic chain applies, reverses to base and re-applies **twice** with zero enum types left behind; the frontend type-checks, lints and production-builds with no warnings.

This document covers the audit you asked for and the 19 items you listed. It is organised by what was actually wrong, because in most cases the reason a page "wasn't working" turned out to be something specific and findable rather than something missing.

---

## Three root causes that explain a lot at once

### 1. Your scheduler was never running

`docker-compose.yml` starts a Celery **worker** and no **beat** process. Every entry in `app/core/celery_app.py`'s `beat_schedule` was dead configuration:

- CVE / EPSS / CISA KEV synchronisation → **CVE Intelligence was empty because nothing ever fetched anything**
- scheduled scans → never fired
- nightly exposure snapshots → **the exposure trend had no points to plot**
- risk-acceptance expiry → lapsed acceptances stayed active
- correlation after sync → new CVEs never matched existing inventory

Added a `beat` service. It runs as its own container rather than `worker -B`, so scaling the worker to more than one replica cannot start a second scheduler and fire everything twice.

### 2. nmap was silently degraded

The worker container is granted `CAP_NET_RAW`, but container capabilities land in **root's** set, and the image runs as the non-root user `ocg_app`. Without file capabilities on the binary, nmap cannot SYN-scan or OS-detect — it quietly falls back to an unprivileged connect scan (no OS detection, no MAC addresses) or fails outright, and the scan records the thinner result as though that were what the network showed. Added `setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap` to the Dockerfile.

### 3. "Queued" had no explanation

`create_scan` committed the `ScanJob` row and *then* called `.delay()`. If the dispatch raised — broker down, no worker, anything — the row was already saved and sat at QUEUED forever. Now a failed dispatch marks the job FAILED with the actual reason, and a new `GET /system/workers` reports whether a worker is online and whether the scheduler has run recently. A banner on the Dashboard and Scan Centre says so plainly.

---

## §3 / §52 — fabricated data, removed

**`app/tasks/discovery_tasks.py` was writing invented records into your inventory.** `discover_cloud_assets` and `discover_identity` described themselves as *"Simulated real-time integration"*. Finding no credentials, they inserted:

```python
CloudResource(name=f"Discovery Failed: {error_msg}", resource_type="Integration::Status", …)
IdentityProfile(email=f"admin_integration_failed@{provider}.local", full_name=f"Integration Error: …")
```

Both were then served by their endpoints as discovered inventory, indistinguishable from real records and counted in any total.

Replaced with a real adapter architecture:

| Integration | Adapter | What it calls |
|---|---|---|
| AWS | `boto3` | `ec2:DescribeInstances` only |
| Azure | `azure-mgmt-resource` | subscription resource list |
| Okta | REST | `GET /api/v1/users` |
| Entra ID | Microsoft Graph | `GET /v1.0/users` |

A new `integration_states` table gives a failed or unconfigured integration somewhere honest to live. **The inventory tables stay empty**, and the UI reports what is missing and how to supply it. 12 tests, the central one being a negative: after an unconfigured or failing run, `CloudResource.count() == 0`.

**Other fabrications removed:**

- `attack_surface_domains.registrar` was set to the string `"Enumerated (Live)"`. No WHOIS or RDAP lookup exists anywhere; the field is now empty with a note saying it is not looked up.
- `identity_profiles.mfa_enabled` defaulted to `false`, so an account whose directory listing simply does not report factor enrolment was recorded as **having MFA disabled** — a security claim nobody made, and one someone would act on. Now nullable; the UI shows three states, and the summary counts "unknown" separately.
- `privilege_level` defaulted to `"USER"`, claiming a privilege level the directory never reported. Now empty means unknown.
- `cloud_resources.compliance_status` — reading an inventory says nothing about compliance. Stays UNKNOWN with the reason on the row.
- `app/scripts/seed_assets.py`, `seed_operations.py`, `seed_discovery.py` — bulk fabricated assets, findings with `random.uniform(0,100)` risk scores, a fake CVE id `"CVE-2023-XXXX"`, invented blocked IPs with attributions like *"Known malicious scanner (C2 infrastructure)"*, a remediation task at `VERIFIED` with no scan evidence, a hardcoded *"### Omni AI Playbook Generated"* string, and **20 forged audit-log entries**. All removed (moved to `_to_delete/removed_seed_scripts/`).
- `app/scripts/check_scans.py` — a script that called `bypass_tenant` and dumped every organization's scans cross-tenant. Removed.
- `graph.py` substituted `{"title": "Finding", "severity": "INFO"}` for a node whose record was gone, putting a benign severity on the graph for something nobody could look up. Unresolved nodes are now flagged and greyed.

---

## §20 — attack path claim strength

`AttackPath` had a single `is_verified` boolean, nothing ever set it to `True`, and the model docstring said the row *"demonstrat[es] how an attacker could move"*. Nothing was demonstrated.

Replaced with `claim_strength`:

- **POTENTIAL** — the relationships composing the route exist. Nothing has been attempted along it.
- **OBSERVED** — activity consistent with the route was seen. Not proof of an attack, not proof it succeeded.
- **VERIFIED** — an authorized verification run traversed it, and `verified_by_scan_job_id` names the run.

Every path the platform computes is POTENTIAL. There is a test that walks the engine's syntax tree and **fails the build if the words VERIFIED or OBSERVED appear in it**, because this platform runs no exploit verification and a later edit that starts claiming otherwise has to be deliberate.

### The engine was also broken in four ways

It was a flat SQL join, and it was never invoked from anywhere — no task, no endpoint, no beat entry — so `GET /attack-paths/` was permanently empty while being presented as working.

- Its central predicate was `exposure_breakdown->>'internet_exposed'`, **a key nothing has ever written**. The real column is `Asset.is_internet_facing`. It matched zero rows, so every organization got "no attack paths" — which reads as a clean estate.
- `path_edges` was always `[]` despite being documented as the ordered edge list. No edge was traversed.
- `risk_score` was `90.0` for CRITICAL / `70.0` for HIGH — invented constants — then silently overwritten by `cvss_score * 10`, which is a vulnerability severity, not a path risk.
- `source_node_id` was `uuid.UUID(int=0)` as a sentinel for "the internet", persisted as a real node id.

Rewritten as a real breadth-first traversal over `graph_edges`, with a documented, explainable risk model whose contributors sum to the displayed score and which declares what it cannot account for. Wired into a new `graph_tasks` module, dispatched after every completed scan and nightly. 18 tests.

---

## §35 — authorization

Five endpoints shipped with `Depends(get_current_user)` and nothing else — the exposure graph, attack paths, attack surface, cloud and identity. They authenticated correctly and returned the right tenant's data. They simply let **any role at all**, including read-only, read the organization's entire asset and finding inventory — and let anyone launch a live probe against any domain on the internet.

Fixed there and in twelve more places, the worst being `audit_logs`, which used `get_current_active_user` so a helpdesk technician could read the whole organization's audit trail. `incidents` used `MANAGE_USERS` with the comment *"Use highest permission for incident management for now"*, which granted incident management to user-admins and denied it to security managers.

`test_endpoint_authorization.py` is a structural guard over the whole API surface. It walks every endpoint module and requires each route to name a permission; a route that genuinely should not is listed in `EXEMPT` **with the reason written down**. There are further tests that the exemption list has no stale entries and that every exemption states a reason — the decision has to be made, not made by omission.

`ws.py` decoded the token and connected without checking it was an access token rather than a refresh token, without loading the user, and without checking the account was still active. A refresh token opened a live feed. Now resolves the user, checks `is_active` and the required permission, and takes the organization from the user record rather than a claim.

---

## §46 — authorized scope, enforced

`Network.is_authorized_scope` is documented as *"the record of consent"*, and `sites.py` states *"discovery and scanning both consult this table"*. **Neither did.** The authorization endpoint existed and was advisory — the Scan Centre called it to *display* a warning — and nothing acted on the answer. The only real gate was a private-range check, which stops a scan of the public internet and stops nothing else.

`app/services/scan_authorization.py` is now the single enforcement point, called from the API, the scheduler and domain probing. Containment is strict: a declared /24 does not authorize the /16 containing it. A refusal is written to the audit log. A scan also requires an explicit confirmation at launch — registering a range once is not standing consent.

Schedules are validated at creation *and* re-checked at dispatch, because an operator may have withdrawn the scope since; a schedule whose target is no longer authorized is deactivated with the reason recorded rather than failing silently every minute.

**Attack surface probing** was the clearest violation: `POST /attack-surface/scan` took any domain string from any authenticated user and dispatched a live DNS + TLS probe at it. Now a domain must be registered as authorized scope first — the row *is* the authorization, carrying who approved it and when — and the probe endpoint takes an id, not free text.

---

## §66 — things that reported success without doing anything

| What | The defect |
|---|---|
| Executive PDF | `generate_executive_report` was annotated `-> bytes`, assembled its elements, and **ended**. No `doc.build()`, no `return`. It returned `None` and the endpoint served HTTP 200 with a PDF filename, PDF content type, and **an empty body**. |
| Both PDF reports | Filtered with `Finding.status == "open"`. The column is an enum stored by member name (`OPEN`), so the predicate matched nothing and **every report stated zero findings regardless of the estate** — a fabricated all-clear. |
| WebSocket notifications | `connect` keyed by the JWT's `org_id` (a string); `broadcast_to_org` was called with `current_user.organization_id` (a UUID). The lookup never matched, so every "Scan initiated" notification was dropped while the request returned 202. |
| Scheduled scans | `check_schedules` queried without a tenant scope. Under enforced RLS the predicate is NULL, so it returned **zero rows every minute, for every organization**. A schedule could be created, shown active, and never fire. |
| Discovery RLS | The Phase 11 migration wrote policies against `current_setting('app.current_tenant')` — a setting the application has never set — and omitted `FORCE ROW LEVEL SECURITY`. Tenant isolation on `cloud_resources`, `identity_profiles` and `attack_surface_domains` was non-functional **in both directions**. |
| Incident playbooks | On LLM failure, `playbook = f"Error generating playbook: {e}"` was **persisted into `incident.ai_playbook`** and returned with a 200. The exception string became the incident's response playbook. |
| Migration reversibility | Two revisions had `op.drop_constraint(None, …)`, which cannot compile. `alembic downgrade base` had **never worked**. Several revisions also left their enum types behind, so even a working downgrade could not be re-applied. CI now round-trips the full chain twice. |
| Scan deletion | A QUEUED scan could not be deleted — and while jobs were stranded at QUEUED by an absent worker, that made them **undeletable entirely**. Bulk delete returned 204 and silently skipped what it could not remove, so selecting ten rows could delete none of them and look like it worked. |

---

## Your 19 items

**1. Dashboard live data + real-time ticker.** The WebSocket only ever raised a toast — it never touched the React Query cache, so a scan finishing left every count on screen stale. It now invalidates the affected queries per event type and reconnects with exponential backoff (a dropped socket was permanent). The ticker keys off `["threat-intel"]`, which the socket invalidates on a threat event. Also: the dashboard stopped calling `api.ipify.org` **from your browser** (a security console reaching out to a third party on every page load, reporting the *browser's* exit address as the platform's), and "SECURE UPLINK" is no longer a permanently-green badge with no state behind it.

**2. Exposure trend + most exposed assets.** The trend was empty because snapshots come from a beat task that was never running. Queries now share the `exposure` key prefix the socket invalidates, with polling as a fallback.

**3. Asset delete + edit.** Delete had **no `onError` anywhere**, so a refusal produced complete silence and looked like a dead button. Errors now surface, deletes confirm, and assets are editable — only `criticality` was changeable before, so a typo in a hostname was permanent.

**4. Sites & networks.** Sites had no edit and no delete at all. Networks had only the two boolean toggles — name, CIDR, VLAN and site were immutable. Both now fully editable and deletable, with warnings that state the consequence (deleting a range does not delete its assets; they lose the declared internet-exposure that feeds their exposure score).

**5, 6, 7. Attack surface, cloud, identity.** Nine calls across these pages used `fetch("/api/v1/…")` — relative to the **frontend** origin, not the API's — so they 404'd on every deployment. That is why they "weren't working". Rebuilt against the new API.

**8. Scans.** Covered above: beat, setcap, dispatch failure, delete. The Scan Centre now sends the authorization confirmation and shows a worker-status banner.

**9. Compliance.** The page read a `coverage_percent` field the API does not return, so nothing rendered. Its only prose was inferred from `coverage_percent < 100` — *"Deficiencies detected…"* or *"Fully Compliant…"* — neither based on a single control result. Rebuilt: real per-control results with evidence, installable packs, and **two** percentages, because a control that could not be evaluated is excluded from the score rather than counted as a pass.

**10. Threat Intelligence.** Read `entries` from the top level; the API returns that nested under `cve_catalogue` alongside `latest_advisories`. `data.entries` was `undefined` and the page rendered nothing. Now shows the two halves separately and deliberately: **your network** (what the passive monitor observed) and **the world** (published CVEs, which say nothing about whether you are affected).

**11. CVE Intelligence.** Empty because the scheduler never ran. Also: `cves.total` does not exist on the response, the search box set state nothing read, the request was a fixed `?size=25` (a parameter the API does not accept), and "Filter" had no handler. Search, severity, known-exploited and pagination now all work server-side.

**12. Remediation.** The TypeScript interface described a completely different shape than the API returns — `due_at` vs `due_date`, `assigned_to` object vs `assigned_to_name`, uppercase vs lowercase enums — so every badge fell through to no colour, every due date rendered blank, and the assignee never appeared. Fixed, plus working search and filters.

**13. Infrastructure protection + firewall.** "Block IP", "Firewall Settings" and "Filter" had **no handlers at all**, and the "Integrations Active" card was the literal markup `<h3>2</h3>` with "Palo Alto" and "AWS WAF" typed beside it. See the section below.

**14. Reports.** The download called `fetch(...)` with **no second argument** — no Authorization header at all — against a relative path. Now goes through the authenticated helper, and the PDFs contain real figures (see §66).

**15. Organizations.** Rename, deactivate (reversible) and delete (typed confirmation, because it cascades to every asset, finding, scan, credential and audit record). Blocked from acting on the organization you are signed in to.

**16. Users.** There was no way to change a user at all once created — no rename, no role reassignment, no reactivation after deactivating. All three added.

**17. Branding.** This was never wired up. `globals.css` hardcodes `--color-primary: 14 165 233`, Tailwind binds every `primary` utility to that variable, and **the only writer was the stylesheet**. Saving showed "Saved successfully!" and changed nothing, forever, including after a reload. Now: a provider that fetches and applies your colours, a hex→RGB-triple conversion (Tailwind's `<alpha-value>` syntax needs `14 165 233`, not `#0EA5E9` — assigning hex directly would have silently broken every `bg-primary/10` in the app), a pre-paint script so there is no flash of default blue, a live preview, and instant application on save. Logo, favicon and footer text render too; the sidebar was hardcoded to a shield icon and "Omni Digital Solution".

**18. Audit logs.** Search by name/email/action/resource/IP, actor and action dropdowns derived from your actual data, date range, pagination, and a PDF export that applies the same filters **and states them on the document** — an audit export whose scope is not recorded on the document is not evidence of anything. Truncation is declared on the first page rather than silently trimming.

**19. Licensing.** Was 100% fabricated: "Omni One", "Enterprise Edition", renewal "Dec 31, 2028", org "Acme Corp Global", tenant `org_7f8a9b2c1d3e4f5`, 8,492 of 10,000 assets, and a bar with `style={{ width: "85%" }}`. Now reads your real plan, seat limit and active-user count, is editable by super-admins, and Contact Sales gives **ykamranali7777@gmail.com**, **+971508169288**, a WhatsApp click-to-chat link and a `tel:` link.

---

## The firewall integration (#13) in detail

New `firewall_integrations` table and real adapters for **OPNsense**, **pfSense** (via pfSense-pkg-API) and **FortiGate**.

Each adapter adds an address to, or removes it from, **a named object you already control** — an alias or an address group. It does not create rules, change policy order, or touch anything else. That boundary is deliberate: you decide what a rule referencing that object does, and the platform only decides what is in it. A tool that can write arbitrary firewall policy through an API is a much larger thing to trust.

**The rule the whole design turns on:** `status = "enforced"` means the vendor's API returned success. Not that the platform thinks it should be blocked, not that a rule was generated for someone to paste. If the push fails the entry stays `recommended` and carries the reason — because an operator reading "enforced" stops looking, and a block that silently did not happen is worse than no block.

An integration only becomes CONNECTED by a round trip that actually succeeded. There is no way to mark it connected by asserting so.

### On automatic blocking

You asked for auto-block. It is built, and it is bounded — the limits are in the schema rather than in application logic, because a platform that can cut off network access on its own judgement should not have those limits be editable by a code change alone:

- **off unless you turn it on**, and it cannot be enabled until a connection test has succeeded — turning it on for a firewall that has never answered would mean the platform believes it is enforcing when it is not;
- only events **at or above a severity you set**;
- a **never-block list** you define (gateway, DNS, management range) that cannot be bypassed, plus loopback and link-local always exempt;
- every automatic block **expires by itself**, so a wrong one heals;
- the decision, the evidence and the vendor's response all go to the audit log.

20 tests, including that a failing firewall leaves the entry at `recommended`, that an exempt address cannot be enforced even manually, and that a failed *withdrawal* does not claim the block is gone.

**What I did not do:** the platform still does not interrupt traffic itself. The previous version tried to, by forging TCP RST packets with a spoofed source address — indistinguishable from an attack, aimable at any host on the segment — and that was removed earlier in this work. Your firewall enforces; the platform asks it to.

---

## Test coverage added this session

| File | Tests | Covers |
|---|---|---|
| `test_scan_authorization_scope.py` | 12 | Strict containment, cross-tenant refusal, malformed ranges authorizing nothing, confirmation required at launch, audit record of refusals |
| `test_discovery_integrations.py` | 12 | The negative assertion — no inventory row after an unconfigured or failing run — plus adapter descriptions, upsert-not-duplicate, unknown MFA preserved as unknown |
| `test_attack_paths.py` | 18 | Real traversal, the internet-exposure column, every hop backed by an edge, no sentinel node, the syntax-tree proof that nothing can be VERIFIED, verified paths surviving recomputation |
| `test_endpoint_authorization.py` | 4 | Every route names a permission; no route relies on bare authentication; no stale exemptions; every exemption states a reason |
| `test_reports_and_exports.py` | 19 | PDFs are real PDFs with content; open findings actually counted; audit filters and PDF export |
| `test_realtime_and_worker_health.py` | 12 | The UUID/string broadcast mismatch in both directions; delivery count; worker and scheduler health, including "unknown" rather than a guess |
| `test_firewall_enforcement.py` | 20 | Enforcement means the vendor accepted it; every automatic-blocking gate individually |

**411 → 581 tests.**

---

## What you need to run

```bash
# Rebuild — the Dockerfile changed (setcap) and there is a new beat service
docker compose build backend
docker compose up -d postgres redis backend worker beat frontend

cd backend
alembic upgrade head        # applies c4d7b2a95e18 and d5e8c3b06f27
pytest -q                   # 581 passed, 1 skipped

cd ../frontend
npm ci && npm run build
```

Then check **Dashboard → the worker banner**. If it says no worker or no scheduler is running, that is the thing to fix before anything else — most of what looked broken was downstream of it.

To enable the integrations that need credentials, see the new sections in `backend/.env.example` (AWS, Azure, Okta/Entra ID, and the AI security engineer). The firewall is configured through the UI, not the environment, because its secret belongs in the encrypted vault.

**Still outstanding from earlier:** delete `_to_delete/` at the repository root. It now holds the removed seed scripts and the transfer archives used to move this work onto your machine.

---

## Two things I could not resolve from here

**A second agent session is committing to this repository.** Commits `a2605db`, `00dea36`, `0dac480`, `d6db673`, `83768d0` are not mine, and the Phase 8 and Phase 11 migrations were written by it. The fabricated discovery tasks, the missing RBAC and the broken RLS policies described above all came from that work. I have fixed them, but I cannot coordinate with that session and we will collide again.

**Cloud and identity cannot show real data without credentials.** There is no honest implementation that produces cloud inventory without an AWS or Azure key, or directory accounts without an Okta or Entra token. Those pages now say exactly what is missing and how to supply it. That is the correct behaviour, not a gap.
