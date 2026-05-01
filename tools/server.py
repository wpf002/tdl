#!/usr/bin/env python3
"""TDL Playbook API server.

Endpoints:
  GET  /api/health                health probe
  GET  /api/stats                 dashboard counts
  GET  /api/rules                 list rules (filters: tactic, severity, lifecycle, q)
  GET  /api/rules/<rule_id>       single rule (full, untruncated)
  GET  /api/tactics               counts grouped by tactic
  GET  /api/coverage              ATT&CK coverage report
  GET  /api/chains                attack chain coverage
  GET  /api/recommendations       log-source recommendations (default profile)

Production mode also serves ui/dist/ so the SPA loads from the same origin.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import jwt
from jwt import PyJWKClient
from flask import Flask, abort, g, jsonify, request, send_from_directory
from flask_cors import CORS

from tools.db import db_enabled, session_scope
from tools.models import Rule

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
RULES_JSON = ROOT / "ui" / "src" / "data" / "rules.json"
DIST = ROOT / "ui" / "dist"
EXPORTS = ROOT / "exports"
MATRIX = ROOT / "matrix"

RULE_COLUMNS = (
    "rule_id", "name", "description",
    "tactic", "tactic_id", "technique_id", "technique_name",
    "platform", "data_sources",
    "severity", "fidelity", "lifecycle", "risk_score",
    "queries", "pseudo_logic", "false_positives", "triage_steps", "tags",
    "test_method", "tuning_guidance",
    "author", "created", "last_modified",
    "org_id", "is_custom",
)

app = Flask(__name__, static_folder=None)
CORS(app)

# ── Auth (Clerk JWT verification on /api/* except /api/health) ──────────────
CLERK_JWT_ISSUER = (os.environ.get("CLERK_JWT_ISSUER") or "").rstrip("/")
PUBLIC_API_PATHS = {"/api/health"}
_jwks_client = None


def _get_jwks_client():
    global _jwks_client
    if _jwks_client is None:
        if not CLERK_JWT_ISSUER:
            raise RuntimeError("CLERK_JWT_ISSUER env var is not set")
        _jwks_client = PyJWKClient(f"{CLERK_JWT_ISSUER}/.well-known/jwks.json")
    return _jwks_client


def _verify_clerk_jwt(token):
    signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=CLERK_JWT_ISSUER,
        options={"verify_aud": False},  # Clerk session tokens omit `aud` by default
    )


@app.before_request
def _auth_gate():
    path = request.path or ""
    if not path.startswith("/api/"):
        return None
    if path in PUBLIC_API_PATHS:
        return None
    if not CLERK_JWT_ISSUER:
        return jsonify(error="server auth misconfigured: CLERK_JWT_ISSUER unset"), 503
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="missing bearer token"), 401
    token = auth[7:].strip()
    try:
        payload = _verify_clerk_jwt(token)
    except Exception as e:
        return jsonify(error=f"invalid token: {type(e).__name__}"), 401
    g.clerk_user_id = payload.get("sub")
    return None

_rules_cache = None


def _row_to_dict(row):
    return {col: getattr(row, col) for col in RULE_COLUMNS}


def load_rules(force=False):
    """Read rules from Postgres if DATABASE_URL is set; else from rules.json.

    Cached in-process; pass force=True to refresh. Postgres-backed reads always
    bypass the cache so edits made through the API are visible immediately.
    """
    global _rules_cache
    if db_enabled():
        with session_scope() as s:
            rows = s.query(Rule).order_by(Rule.rule_id).all()
            return [_row_to_dict(r) for r in rows]

    if _rules_cache is not None and not force:
        return _rules_cache
    if not RULES_JSON.exists() or force:
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "export_ui_data.py")],
            check=True,
            cwd=ROOT,
        )
    with RULES_JSON.open("r", encoding="utf-8") as f:
        _rules_cache = json.load(f)
    return _rules_cache


def load_full_rule(rule_id):
    """Load a single rule with full (untruncated) fields.

    With Postgres: reads the row directly. Without: reads from YAML.
    """
    if db_enabled():
        with session_scope() as s:
            row = s.query(Rule).filter(Rule.rule_id == rule_id).one_or_none()
            return _row_to_dict(row) if row else None

    import yaml
    for path in RULES_DIR.rglob("*.yaml"):
        with path.open("r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if isinstance(doc, dict) and doc.get("rule_id") == rule_id:
            return doc
    return None


@app.get("/api/health")
def health():
    return jsonify(status="ok", rules=len(load_rules()))


@app.get("/api/stats")
def stats():
    rules = load_rules()
    by_tactic, by_severity, by_lifecycle = {}, {}, {}
    for r in rules:
        by_tactic[r.get("tactic")] = by_tactic.get(r.get("tactic"), 0) + 1
        by_severity[r.get("severity")] = by_severity.get(r.get("severity"), 0) + 1
        by_lifecycle[r.get("lifecycle")] = by_lifecycle.get(r.get("lifecycle"), 0) + 1
    return jsonify(
        total=len(rules),
        by_tactic=by_tactic,
        by_severity=by_severity,
        by_lifecycle=by_lifecycle,
    )


@app.get("/api/rules")
def list_rules():
    rules = load_rules()
    tactic = request.args.get("tactic")
    severity = request.args.get("severity")
    lifecycle = request.args.get("lifecycle")
    q = (request.args.get("q") or "").lower().strip()

    out = rules
    if tactic and tactic != "All":
        out = [r for r in out if r.get("tactic") == tactic]
    if severity and severity != "All":
        out = [r for r in out if r.get("severity") == severity]
    if lifecycle and lifecycle != "All":
        out = [r for r in out if r.get("lifecycle") == lifecycle]
    if q:
        def matches(r):
            return (
                q in (r.get("name") or "").lower()
                or q in (r.get("rule_id") or "").lower()
                or q in (r.get("technique_id") or "").lower()
                or any(q in (t or "").lower() for t in (r.get("tags") or []))
            )
        out = [r for r in out if matches(r)]
    return jsonify(out)


@app.get("/api/rules/<rule_id>")
def get_rule(rule_id):
    full = request.args.get("full") == "1"
    if full:
        doc = load_full_rule(rule_id)
        if doc is None:
            abort(404)
        return jsonify(doc)
    for r in load_rules():
        if r.get("rule_id") == rule_id:
            return jsonify(r)
    abort(404)


@app.get("/api/tactics")
def tactics():
    rules = load_rules()
    grouped = {}
    for r in rules:
        t = r.get("tactic") or "Unknown"
        bucket = grouped.setdefault(t, {"tactic_id": r.get("tactic_id"), "count": 0, "deployed": 0, "techniques": set()})
        bucket["count"] += 1
        if r.get("lifecycle") == "Deployed":
            bucket["deployed"] += 1
        if r.get("technique_id"):
            bucket["techniques"].add(r["technique_id"])
    out = []
    for name, b in grouped.items():
        out.append({
            "tactic": name,
            "tactic_id": b["tactic_id"],
            "count": b["count"],
            "deployed": b["deployed"],
            "techniques": sorted(b["techniques"]),
        })
    out.sort(key=lambda x: -x["count"])
    return jsonify(out)


@app.get("/api/coverage")
def coverage():
    p = MATRIX / "coverage_report.json"
    if not p.exists() or request.args.get("refresh"):
        subprocess.run(["node", str(ROOT / "tools" / "coverage.js")], check=True, cwd=ROOT)
    with p.open("r", encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.get("/api/chains")
def chains():
    out = EXPORTS / "chain_coverage.json"
    if not out.exists() or request.args.get("refresh"):
        EXPORTS.mkdir(exist_ok=True)
        subprocess.run([
            sys.executable, str(ROOT / "tools" / "chain_eval.py"),
            "--rules", str(RULES_DIR),
            "--chains", str(ROOT / "chains" / "attack_chains.yaml"),
            "--output", str(out),
        ], check=True, cwd=ROOT)
    with out.open("r", encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.get("/api/recommendations")
def recommendations():
    out = EXPORTS / "latest_recommendations.json"
    if not out.exists() or request.args.get("refresh"):
        EXPORTS.mkdir(exist_ok=True)
        subprocess.run([
            sys.executable, str(ROOT / "tools" / "recommend.py"),
            "--profile", str(ROOT / "profiles" / "default.yaml"),
            "--catalog", str(ROOT / "log-sources" / "catalog.yaml"),
            "--rules", str(RULES_DIR),
            "--output", str(out),
        ], check=True, cwd=ROOT)
    with out.open("r", encoding="utf-8") as f:
        return jsonify(json.load(f))


# ── Production: serve built SPA from same origin ────────────────────────────
@app.get("/")
def index():
    if not (DIST / "index.html").exists():
        return jsonify(
            message="TDL Playbook API",
            hint="UI not built. Run: npm run ui:build, or use the dev server: npm run app",
            endpoints=[r.rule for r in app.url_map.iter_rules() if r.rule.startswith("/api/")],
        )
    return send_from_directory(DIST, "index.html")


@app.get("/<path:path>")
def static_files(path):
    if not DIST.exists():
        abort(404)
    target = DIST / path
    if target.is_file():
        return send_from_directory(DIST, path)
    return send_from_directory(DIST, "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8787))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"TDL Playbook API → http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
