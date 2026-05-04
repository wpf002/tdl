"""Integration tests for Phase 3 (rule editor) + Phase 3.5 (org profile).

Spins up against a real Postgres instance (DATABASE_URL must point at a
test DB). Bypasses Clerk JWT verification by monkey-patching the auth gate.

Run: DATABASE_URL=postgresql://... python -m tools.test_phase3
"""

import json
import os
import sys

from dotenv import load_dotenv
load_dotenv()


def main():
    if not os.environ.get("DATABASE_URL"):
        print("DATABASE_URL not set — aborting.", file=sys.stderr)
        return 1

    # Migrate + seed a single rule we control.
    from tools import migrate, models
    from tools.db import get_engine, session_scope
    migrate.main()

    with session_scope() as s:
        s.query(models.OrgProfile).delete()
        s.query(models.Rule).delete()
        s.add(models.Rule(
            rule_id="TDL-TEST-001",
            name="Seeded test rule",
            description="Original description",
            tactic="Execution", tactic_id="TA0002",
            technique_id="T1059", technique_name="Command and Scripting Interpreter",
            platform=["Windows"], data_sources=["Process Creation"],
            severity="Medium", fidelity="Medium", lifecycle="Proposed",
            risk_score=50,
            queries={"spl": "index=main foo", "kql": "DeviceProcessEvents"},
            pseudo_logic="if A then B",
            false_positives=["legit usage"],
            triage_steps=["check parent", "check user"],
            tags=["red-team"],
            test_method="Atomic",
            tuning_guidance="Tune by user",
            author="seed", created="2026-05-04", last_modified="2026-05-04",
            is_custom=False,
        ))

    # Patch the JWT gate so we can hit /api/* without a real Clerk token.
    import flask
    from tools import server
    server.CLERK_JWT_ISSUER = "https://test.example.com"

    @server.app.before_request
    def _fake_auth():
        path = flask.request.path or ""
        if not path.startswith("/api/") or path == "/api/health":
            return None
        flask.g.clerk_user_id = "user_TEST123"
        return None

    # Strip the original auth gate so only the fake fires.
    server.app.before_request_funcs[None] = [
        f for f in server.app.before_request_funcs[None]
        if f.__name__ != "_auth_gate"
    ]

    client = server.app.test_client()
    failures = []

    def check(name, ok, detail=""):
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {name}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    # ── Phase 3: rule editor ────────────────────────────────────────────────
    print("\nPhase 3 — rule editor")

    # GET baseline
    r = client.get("/api/rules/TDL-TEST-001")
    check("GET baseline rule", r.status_code == 200 and r.get_json()["name"] == "Seeded test rule",
          f"status={r.status_code}")

    # PUT edit
    r = client.put("/api/rules/TDL-TEST-001", json={
        "name": "Edited name",
        "description": "Edited description",
        "severity": "High",
        "risk_score": 80,
        "tags": ["edited", "phase3"],
        "queries": {"spl": "index=main bar", "kql": "DeviceProcessEvents | where x"},
    })
    body = r.get_json()
    check("PUT updates fields", r.status_code == 200 and body["name"] == "Edited name"
          and body["severity"] == "High" and body["risk_score"] == 80
          and body["tags"] == ["edited", "phase3"]
          and body["queries"]["spl"] == "index=main bar",
          f"status={r.status_code}")
    check("PUT sets is_custom=true", body.get("is_custom") is True)
    check("PUT bumps last_modified", bool(body.get("last_modified")))

    # PUT rejects unknown fields
    r = client.put("/api/rules/TDL-TEST-001", json={"is_custom": False, "rule_id": "HACK"})
    check("PUT rejects body with no editable fields", r.status_code == 400)

    # PUT rejects non-dict queries
    r = client.put("/api/rules/TDL-TEST-001", json={"queries": "string"})
    check("PUT rejects non-dict queries", r.status_code == 400)

    # PUT 404 on missing rule
    r = client.put("/api/rules/TDL-MISSING", json={"name": "x"})
    check("PUT 404 on missing rule", r.status_code == 404)

    # POST duplicate
    r = client.post("/api/rules/TDL-TEST-001/duplicate")
    body = r.get_json()
    new_rid = body.get("rule_id") if body else None
    check("POST duplicate returns 201",
          r.status_code == 201 and new_rid == "TDL-TEST-001-COPY-1"
          and body["lifecycle"] == "Proposed" and body["is_custom"] is True
          and body["name"].endswith("(Copy)"),
          f"status={r.status_code} new_rid={new_rid}")

    # Second duplicate increments suffix
    r = client.post("/api/rules/TDL-TEST-001/duplicate")
    body = r.get_json()
    check("POST duplicate increments suffix",
          r.status_code == 201 and body["rule_id"] == "TDL-TEST-001-COPY-2",
          f"got {body.get('rule_id') if body else None}")

    # DELETE soft delete
    r = client.delete("/api/rules/TDL-TEST-001")
    body = r.get_json()
    check("DELETE marks lifecycle=Retired",
          r.status_code == 200 and body["lifecycle"] == "Retired" and body["is_custom"] is True)

    # ── Phase 3.5: org profile ──────────────────────────────────────────────
    print("\nPhase 3.5 — org profile")

    # GET when none exists → null
    r = client.get("/api/org-profile")
    check("GET org-profile returns null when missing",
          r.status_code == 200 and r.get_json() is None,
          f"status={r.status_code}")

    # PUT requires org_name
    r = client.put("/api/org-profile", json={"primary_siem": "spl"})
    check("PUT org-profile rejects missing org_name", r.status_code == 400)

    # PUT rejects non-list log_sources
    r = client.put("/api/org-profile", json={"org_name": "x", "log_sources_deployed": "nope"})
    check("PUT org-profile rejects non-list log_sources", r.status_code == 400)

    # PUT creates row
    r = client.put("/api/org-profile", json={
        "org_name": "Acme Security",
        "primary_siem": "kql",
        "log_sources_deployed": ["sysmon", "edr"],
    })
    body = r.get_json()
    check("PUT creates org-profile",
          r.status_code == 200 and body["org_name"] == "Acme Security"
          and body["primary_siem"] == "kql"
          and body["log_sources_deployed"] == ["sysmon", "edr"]
          and body["user_id"] == "user_TEST123"
          and bool(body.get("created_at")) and bool(body.get("updated_at")))

    # GET returns it
    r = client.get("/api/org-profile")
    body = r.get_json()
    check("GET org-profile returns saved row",
          r.status_code == 200 and body and body["org_name"] == "Acme Security")

    # PUT updates (idempotent upsert)
    r = client.put("/api/org-profile", json={
        "org_name": "Acme v2",
        "primary_siem": "spl",
        "log_sources_deployed": ["sysmon"],
    })
    body = r.get_json()
    check("PUT upserts existing row",
          r.status_code == 200 and body["org_name"] == "Acme v2"
          and body["log_sources_deployed"] == ["sysmon"])

    # Confirm only one row exists for this user
    with session_scope() as s:
        n = s.query(models.OrgProfile).filter(
            models.OrgProfile.user_id == "user_TEST123"
        ).count()
    check("Only one row per user_id", n == 1, f"count={n}")

    # ── Summary ─────────────────────────────────────────────────────────────
    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
