# Pending deletion

These files were removed from Omni Cyber Guard during the Phase 1 "Truth &
Foundation" cleanup. They are parked here because the tooling that moved them
cannot delete files on this machine.

**Please delete this entire `_to_delete/` folder**, then commit.

## Why each file was removed

### `backend_app_scanners/openvas.py`
Contained no OpenVAS/GVM integration whatsoever. `is_available()` returned a
hardcoded `True`, the scan "progress" was `time.sleep()` calls printing invented
log lines ("Loaded 140,293 active vulnerability signatures"), and it returned
three hardcoded findings — CVE-2024-21412, CVE-2024-3094 and an SMBv1 finding —
with fabricated evidence strings. Those findings were written to the database
and counted on the dashboard as if a real scan had produced them.

### `backend_app_scanners/zap.py`
Same pattern. It claimed successful exploitation that never occurred, including
the evidence string "Payload ' OR '1'='1 successfully bypassed the query logic
on the target endpoint." No ZAP daemon or API client existed in the codebase.

Both engines are scheduled for reimplementation as genuine adapters
(`python-gvm` GMP for Greenbone, the ZAP daemon API for ZAP) in Phase 3.

---

## Also in this folder

`ocg-backend.tgz` and `ocg-frontend.tgz` are temporary archives created to run
the test suite and the Next.js build in a Linux environment for verification.
They are not part of the project and can be deleted with the rest of this folder.
