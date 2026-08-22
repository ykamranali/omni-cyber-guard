# Phase 12 — Grounding the AI security engineer

**Status:** complete, verified.
**Verification:** 484 backend tests pass against PostgreSQL 16 (up from 411); the full Alembic chain now applies, reverses to base, and re-applies twice with nothing left behind; the frontend type-checks, lints and builds clean.

---

## What was there before

`backend/app/agents/security_engineer.py` was 66 lines. It did this:

```python
findings = self.db.query(Finding).filter(...).limit(50).all()
context_lines = [f"Total Assets: {len(assets)}", "Open Findings Context (up to 50):"]
...
full_prompt = f"{SYSTEM_PROMPT}\n\nCONTEXT:\n{context}\n\nUSER PROMPT:\n{prompt}"
response = requests.post(f"{LLM_API_BASE}/generate", json=payload, timeout=30)
return data.get("response", "No response generated.")
```

Three consequences followed from that shape, and none of them could be fixed by editing the system prompt — which already said "NEVER invent or hallucinate scan evidence".

**The model could only see what the context builder happened to include.** Fifty finding titles and an asset count. Ask "which of my internet-facing hosts has a known-exploited vulnerability" and nothing in the context answers it, so the model answered from training data. There was no mechanism by which it could have done otherwise.

**Nothing distinguished a statement backed by a record from one that was not.** The completion went straight into the response body. An invented CVE identifier is shaped exactly like a real one.

**An unreachable model produced text, not a status.** The exception handler returned `f"Error: Unable to reach the LLM provider... Exception: {e}"` *as the assistant's answer*, and the page rendered it in the same panel, in the same typeface, as analysis.

The page around it made claims of its own. It opened every session with a hardcoded greeting — *"I have full context of your organization's attack surface, vulnerabilities, and active incidents"* — and carried a permanent green **LLM Active** badge that was rendered unconditionally, whether or not any model existed.

---

## What replaces it

### 1. Retrieval instead of a context dump — `app/agents/tools.py`

Eleven read-only tools, exposed to the model through native tool calling. It asks for what it needs; each call runs a real query and returns rows.

| Tool | Returns |
|---|---|
| `count_findings` | Counts grouped by severity, status or class |
| `search_findings` | Filtered findings, highest risk first, with citable references |
| `get_finding` | One finding with verbatim scanner evidence |
| `count_assets` / `search_assets` / `get_asset` | Inventory, services, software, classification evidence |
| `explain_asset_exposure` | The contributor breakdown behind a score |
| `list_remediation_tasks` | Tasks, soonest due first |
| `get_compliance_status` | Latest assessment per framework |
| `get_cve_intelligence` | One CVE from the local NVD/EPSS/KEV store |
| `list_recent_scans` | What has actually been assessed |

Three properties hold for every one of them, and each is enforced by a test:

- **Read-only.** `test_no_retrieval_tool_writes_to_the_database` calls all eleven and asserts the session stages no INSERT, UPDATE or DELETE. A second test walks the module's syntax tree and fails the build if a session write appears anywhere in it — because the behavioural test only covers tools that exist today.
- **Tenant-scoped.** Every query filters `organization_id` explicitly, on top of the row-level security already on the session. Two independent mechanisms must fail for one organization to see another's data.
- **Bounded, and honest about it.** Over the row cap, the payload carries `truncated: true` and *"Only the first N of M matching records are shown. Do not describe this as the complete set."*

Tools the caller's role does not permit are not offered to the model at all. A helpdesk technician's session has no compliance tool in its schema list, so the model cannot reach data the operator could not reach themselves.

Empty results carry their own note: *"No records matched. This means the database holds no such data, not that the environment is clean."* An unsynchronised CVE returns *"...has not been synchronised, not that it does not exist. Do not describe its severity, impact or exploitability from memory."*

### 2. Grounding validation — `app/agents/grounding.py`

Every draft is checked against the evidence set: the union of record references the tools actually returned this request. CVE identifiers, record UUIDs, IPv4 addresses and inventory-shaped hostnames are extracted from the answer and matched against it.

- Everything traceable → shown.
- Something untraceable → **withheld**. The operator sees which identifiers could not be traced and that an answer was withheld, not the answer.
- Nothing retrieved at all, but specifics asserted → withheld.
- Nothing retrieved and nothing specific claimed → allowed; this is the honest "no data" answer.

A withheld draft is stored in `agent_messages.withheld_draft`, deliberately in a different column from `content`, and the conversation API never returns it. It is evidence about the model's behaviour, not analysis.

**What this does not catch, stated in the module and in the UI:** wrong *quantities* and wrong *characterisations*. "You have 40 critical findings" when the tool returned 12 passes this check. Two things mitigate it — the retrieved records are attached to every response so they can be compared directly, and the response payload names what was and was not validated — but neither is a substitute for reading the evidence, and the page says so under the input box rather than claiming the answer is verified.

Getting this right took one real correction during development: a UUID has the same shape as an inventory hostname, so a *correctly* cited record identifier was being read as an invented host and good answers were being withheld. The extractor now claims the more specific patterns first, and three tests pin that down.

### 3. Configuration is explicit and off by default — `app/agents/provider.py`

Two transports, both with native tool calling: `openai_compatible` (OpenAI, vLLM, LiteLLM, llama.cpp server, Groq, Azure OpenAI) and `ollama`. There is no free-text fallback; a model that cannot call tools cannot be used, by design.

`GET /agent/status` answers the operator's actual question:

```json
{"configured": false,
 "missing": ["AGENT_LLM_PROVIDER", "AGENT_LLM_BASE_URL", "AGENT_LLM_MODEL"],
 "why_required": "The security engineer summarises findings that already exist in your database...",
 "how_to_enable": "Set these in the backend environment and restart the API: ...",
 "implemented_in": "backend/app/agents/provider.py"}
```

An unreachable model raises `ProviderUnavailable`. There is no code path that puts an error string into the answer field, and a test asserts it: `available: false`, `answer: ""`, reason in its own field.

### 4. Actions require a human — `app/agents/actions.py`

The agent cannot change anything. When it concludes something should be done it calls `propose_action`, which records a proposal and returns *"This has NOT been carried out."*

- **The effect summary is written by the platform, not the model.** It is generated from validated parameters, so what the operator reads is what the executor will do.
- **Validation runs twice** — at proposal time and again at confirmation, because the world changes in between. A finding accepted as a risk while the proposal sat in the queue cannot acquire remediation work; the proposal lands in `FAILED` with the reason.
- **Permission is checked against the confirming human**, not the proposer. A read-only account cannot execute a proposal an admin's session produced.
- Proposals expire (default 60 minutes) rather than executing against stale facts.

Two action types exist: `create_remediation_task` and `assign_remediation_task`. **Risk acceptance is deliberately absent** — it suppresses a finding for a period a person must own, and no part of that belongs to a model even behind a confirmation. A test asserts the registry contains exactly those two, so adding a third is a decision someone has to make explicitly.

### 5. Auditability — migration `b8e5a2f71c93`

`agent_conversations`, `agent_messages`, `agent_action_proposals`, all three under forced row-level security. The transcript records which retrievals ran with what arguments and how many rows came back, the evidence set behind each answer, and the grounding verdict. An assistant that comments on security posture has to be reviewable after the fact.

### 6. The page — `frontend/app/(dashboard)/ask-agent/page.tsx`

The greeting and the unconditional badge are gone. In their place: the badge reflects what `/agent/status` reports, so a disabled assistant looks disabled; an unconfigured deployment gets a panel naming the missing variables and how to set them; and every answer carries a grounding badge, an expandable evidence panel showing the queries that ran and the rows they returned, and any proposals as cards with **Confirm** / **Reject**.

---

## Migration reversibility — fixed along the way

Verifying the Phase 12 migration turned up something worse than the migration itself: **`alembic downgrade base` had never worked.**

Two revisions carried autogenerated `op.drop_constraint(None, 'findings', type_='foreignkey')` calls, which cannot be compiled — an unnamed constraint has no name to drop. The chain raised `CompileError` and stopped. Nobody noticed because CI only ever stepped back one revision.

Behind that, several revisions dropped their tables but left their enum types behind, so even a working downgrade could not be re-applied: `type "assettype" already exists`.

Fixed in `b3faca151c76`, `3ebd9d23ee73`, `e88182b329aa` and `d3966aec788e`. CI now runs `downgrade base` → `upgrade head` **twice**, which proves both that the chain reverses and that a reverted database can be brought back up. Verified locally: two full round trips, zero enum types left in `public`.

---

## Tests — 73 new

| File | Covers |
|---|---|
| `test_agent_grounding.py` (22) | Reference extraction including the UUID/hostname/CVE/IP overlaps; acceptance, rejection, the no-evidence refusal; that the report declares what it does not check |
| `test_agent_tools.py` (17) | Real counts from the database, closed findings excluded, declared truncation, citable references, cross-tenant refusal, per-role tool availability, the row cap, and the two read-only proofs |
| `test_agent_loop.py` (22) | Unconfigured and unreachable models produce no content; tools offered rather than context dumped; fabricated CVEs withheld; withheld drafts stored but not returned; tool errors returned to the model not the operator; the iteration budget; the full action gate |
| `test_agent_api.py` (12) | Authentication on every route, a permissionless role refused, cross-tenant conversation and proposal access, the status payload, and a syntax-tree check that no future route can be added with `get_current_user` alone |

That last one exists because of something in this repository right now — see below.

---

## Two things needing your attention

**1. Another agent session is committing to this repository.** Commits `a2605db`, `00dea36`, `0dac480`, `d6db673`, `83768d0` are not mine, and two migrations in the chain (`a5ff3fd8cd85` Phase 8, `42e91f847792` Phase 11, still uncommitted) were written by it. Nothing of mine was overwritten and `router.py` carries both sets of routes cleanly — but we will collide eventually, and I cannot coordinate with it.

**2. `backend/app/tasks/discovery_tasks.py` fabricates database records.** `discover_cloud_assets` and `discover_identity` describe themselves as *"Simulated real-time integration"* and write invented rows — `CloudResource(name="Discovery Failed: ...")`, `IdentityProfile(email="admin_integration_failed@...")`. That is what §3 and §52 forbid. `discover_attack_surface` in the same file is real (DNS resolution, live TLS certificate retrieval) and should be kept.

Also: the five endpoints from that work (`graph.py`, `attack_paths.py`, `attack_surface.py`, `cloud.py`, `identity.py`) authenticate with `Depends(get_current_user)` but carry no `require_permission`, and none of those modules has a test. The syntax-tree guard added in `test_agent_api.py` is scoped to the agent surface; extending it across all endpoints would fail the build today, which is why it is not yet extended.

---

## Still to run on your machine

```bash
cd backend
alembic upgrade head        # applies b8e5a2f71c93
pytest -q                   # 484 passed, 1 skipped

cd ../frontend
npm run build
```

And still outstanding from Phase 1: **delete `_to_delete/`** at the repository root. It now also holds the two transfer archives used to move this phase's files onto the machine.
