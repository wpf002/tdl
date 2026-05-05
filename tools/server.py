#!/usr/bin/env python3
"""TDL Playbook API server.

Endpoints:
  GET    /api/health                       health probe
  GET    /api/stats                        dashboard counts
  GET    /api/rules                        list rules (filters: tactic, severity, lifecycle, q)
  GET    /api/rules/<rule_id>              single rule (full, untruncated)
  PUT    /api/rules/<rule_id>              edit rule (Postgres-only; sets is_custom=true)
  DELETE /api/rules/<rule_id>              soft delete (lifecycle=Retired)
  POST   /api/rules/<rule_id>/duplicate    duplicate rule (new rule_id)
  GET    /api/rules/export                 rule library as zip of YAML files (DaaC export)
  GET    /api/tactics                      counts grouped by tactic
  GET    /api/coverage                     ATT&CK coverage report
  GET    /api/coverage/export              coverage report as JSON / CSV / PDF (?format=)
  GET    /api/chains                       attack chain coverage
  GET    /api/recommendations              log-source recommendations (default profile)
  GET    /api/org-profile                  current user's org profile (or null)
  PUT    /api/org-profile                  upsert current user's org profile
  POST   /api/rules/generate               AI rule builder — returns preview + usage (Phase 4 ⚠ cost)
  POST   /api/rules                        save a (typically AI-generated) rule
  GET    /api/ai-usage                     current user's AI spend today + cap
  POST   /api/rules/import                 import Sigma YAML or SIEM-dialect query → TDL rules (Phase 5 ⚠ cost)
  GET    /api/import-jobs                  list current user's recent import jobs
  GET    /api/import-jobs/<id>             check status of a specific import job
  POST   /api/import-jobs/<id>/apply       review-and-apply: save staged rules (optional subset)

Production mode also serves ui/dist/ so the SPA loads from the same origin.
"""

import csv
import io
import json
import os
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

import uuid

from flask import Flask, Response, abort, g, jsonify, make_response, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from tools.db import db_enabled, session_scope
from tools.models import AIUsage, AuthToken, DeletedRule, ImportJob, OrgProfile, Rule, User
from tools import auth as authlib

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
# Cookies must be sent on cross-origin requests (vite dev server → flask api),
# so CORS needs supports_credentials and an explicit origin (cannot be '*').
_DEV_ORIGINS = [o.strip() for o in (os.environ.get("CORS_ORIGINS") or "http://localhost:5173").split(",") if o.strip()]
CORS(app, supports_credentials=True, origins=_DEV_ORIGINS)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],  # no global limit; auth endpoints opt-in below
    storage_uri="memory://",
)

# Process-start timestamp + build commit, surfaced via /api/health so the
# deploy pipeline can verify the running pod is actually the freshly-built
# image (a stale pod will report an old started_at + old commit).
_STARTED_AT = time.time()


def _build_commit():
    return (
        os.environ.get("RAILWAY_GIT_COMMIT_SHA")
        or os.environ.get("BUILD_COMMIT")
        or "unknown"
    )[:12]

# ── Auth (session-cookie gate on /api/* except public paths) ────────────────
PUBLIC_API_PATHS = {
    "/api/health",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/forgot-password",
    "/api/auth/reset-password",
    "/api/auth/verify-email",
}


@app.before_request
def _auth_gate():
    path = request.path or ""
    if not path.startswith("/api/"):
        return None
    if path in PUBLIC_API_PATHS:
        return None
    cookie = request.cookies.get(authlib.SESSION_COOKIE_NAME, "")
    user_id = authlib.read_session_cookie(cookie)
    if not user_id:
        return jsonify(error="unauthenticated"), 401
    g.user_id = user_id
    return None


# ── /api/auth/* endpoints ────────────────────────────────────────────────────

def _user_to_dict(u: User):
    return {
        "id": u.id,
        "email": u.email,
        "email_verified": u.email_verified,
        "created_at": u.created_at,
        "last_login_at": u.last_login_at,
    }


def _set_session_cookie(resp, user_id: str):
    resp.set_cookie(
        authlib.SESSION_COOKIE_NAME,
        authlib.issue_session_cookie(user_id),
        **authlib.session_cookie_kwargs(),
    )


def _clear_session_cookie(resp):
    resp.set_cookie(
        authlib.SESSION_COOKIE_NAME, "",
        max_age=0, httponly=True,
        secure=authlib.session_cookie_kwargs().get("secure", False),
        samesite="Lax", path="/",
    )


@app.post("/api/auth/register")
@limiter.limit("10 per hour")
def auth_register():
    _require_db("registration")
    body = request.get_json(silent=True) or {}
    email = authlib.normalize_email(body.get("email") or "")
    password = body.get("password") or ""
    if not authlib.looks_like_email(email):
        return jsonify(error="Please enter a valid email address."), 400
    err = authlib.validate_password_strength(password)
    if err:
        return jsonify(error=err), 400

    with session_scope() as s:
        existing = s.query(User).filter(User.email == email).one_or_none()
        if existing is not None:
            # Don't leak which emails are registered. Behave like success but
            # send no email and return a generic message; the SignUp form will
            # invite them to log in. We return 409 so the UI can hint at login.
            return jsonify(error="An account with this email already exists."), 409

        user_id = uuid.uuid4().hex
        now = authlib._now_iso()
        user = User(
            id=user_id,
            email=email,
            password_hash=authlib.hash_password(password),
            email_verified=False,
            created_at=now,
            last_login_at=now,
        )
        s.add(user)

        plaintext, digest = authlib.generate_token()
        s.add(AuthToken(
            token_hash=digest,
            user_id=user_id,
            purpose="verify_email",
            created_at=now,
            expires_at=authlib.token_expiry("verify_email"),
        ))
        s.flush()
        snapshot = _user_to_dict(user)

    try:
        authlib.send_verification_email(email, plaintext)
    except Exception as e:
        app.logger.warning("verification email failed: %s", e)

    resp = make_response(jsonify(user=snapshot))
    _set_session_cookie(resp, snapshot["id"])
    return resp


@app.post("/api/auth/login")
@limiter.limit("20 per 5 minutes")
def auth_login():
    _require_db("login")
    body = request.get_json(silent=True) or {}
    email = authlib.normalize_email(body.get("email") or "")
    password = body.get("password") or ""
    if not email or not password:
        return jsonify(error="Email and password are required."), 400

    with session_scope() as s:
        user = s.query(User).filter(User.email == email).one_or_none()
        # Constant-ish-time: still call verify_password against a dummy hash
        # when the user doesn't exist, to reduce email-enumeration via timing.
        ok = False
        if user is not None:
            ok = authlib.verify_password(password, user.password_hash)
        else:
            authlib.verify_password(password, "$2b$12$" + "x" * 53)
        if not user or not ok:
            return jsonify(error="Invalid email or password."), 401
        user.last_login_at = authlib._now_iso()
        s.flush()
        snapshot = _user_to_dict(user)

    resp = make_response(jsonify(user=snapshot))
    _set_session_cookie(resp, snapshot["id"])
    return resp


@app.post("/api/auth/logout")
def auth_logout():
    resp = make_response(jsonify(ok=True))
    _clear_session_cookie(resp)
    return resp


@app.get("/api/auth/me")
def auth_me():
    user_id = g.get("user_id")
    if not user_id:
        abort(401)
    _require_db("auth")
    with session_scope() as s:
        user = s.query(User).filter(User.id == user_id).one_or_none()
        if user is None:
            # Stale cookie pointing at a deleted user — clear it.
            resp = make_response(jsonify(error="user not found"), 401)
            _clear_session_cookie(resp)
            return resp
        return jsonify(user=_user_to_dict(user))


@app.post("/api/auth/forgot-password")
@limiter.limit("5 per hour")
def auth_forgot_password():
    _require_db("password reset")
    body = request.get_json(silent=True) or {}
    email = authlib.normalize_email(body.get("email") or "")
    # Always return ok to avoid email enumeration.
    if not authlib.looks_like_email(email):
        return jsonify(ok=True)

    with session_scope() as s:
        user = s.query(User).filter(User.email == email).one_or_none()
        if user is None:
            return jsonify(ok=True)
        plaintext, digest = authlib.generate_token()
        now = authlib._now_iso()
        s.add(AuthToken(
            token_hash=digest,
            user_id=user.id,
            purpose="reset_password",
            created_at=now,
            expires_at=authlib.token_expiry("reset_password"),
        ))
        s.flush()

    try:
        authlib.send_password_reset_email(email, plaintext)
    except Exception as e:
        app.logger.warning("reset email failed: %s", e)
    return jsonify(ok=True)


@app.post("/api/auth/reset-password")
@limiter.limit("10 per hour")
def auth_reset_password():
    _require_db("password reset")
    body = request.get_json(silent=True) or {}
    token = body.get("token") or ""
    password = body.get("password") or ""
    if not token:
        return jsonify(error="Missing token."), 400
    err = authlib.validate_password_strength(password)
    if err:
        return jsonify(error=err), 400

    digest = authlib.hash_token(token)
    now = authlib._now_iso()
    with session_scope() as s:
        row = s.query(AuthToken).filter(
            AuthToken.token_hash == digest,
            AuthToken.purpose == "reset_password",
        ).one_or_none()
        if row is None or row.used_at is not None or authlib.is_token_expired(row.expires_at):
            return jsonify(error="This reset link is invalid or has expired."), 400
        user = s.query(User).filter(User.id == row.user_id).one_or_none()
        if user is None:
            return jsonify(error="This reset link is invalid or has expired."), 400
        user.password_hash = authlib.hash_password(password)
        row.used_at = now
        s.flush()
        snapshot = _user_to_dict(user)

    resp = make_response(jsonify(user=snapshot))
    _set_session_cookie(resp, snapshot["id"])
    return resp


@app.post("/api/auth/verify-email")
@limiter.limit("20 per hour")
def auth_verify_email():
    _require_db("email verification")
    body = request.get_json(silent=True) or {}
    token = body.get("token") or ""
    if not token:
        return jsonify(error="Missing token."), 400

    digest = authlib.hash_token(token)
    now = authlib._now_iso()
    with session_scope() as s:
        row = s.query(AuthToken).filter(
            AuthToken.token_hash == digest,
            AuthToken.purpose == "verify_email",
        ).one_or_none()
        if row is None or row.used_at is not None or authlib.is_token_expired(row.expires_at):
            return jsonify(error="This verification link is invalid or has expired."), 400
        user = s.query(User).filter(User.id == row.user_id).one_or_none()
        if user is None:
            return jsonify(error="This verification link is invalid or has expired."), 400
        user.email_verified = True
        row.used_at = now
        s.flush()
        return jsonify(ok=True)


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
    return jsonify(
        status="ok",
        rules=len(load_rules()),
        commit=_build_commit(),
        started_at=_STARTED_AT,
    )


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


# ── Rule mutations (Postgres-only) ──────────────────────────────────────────

EDITABLE_RULE_FIELDS = {
    "name", "description",
    "tactic", "tactic_id", "technique_id", "technique_name",
    "platform", "data_sources",
    "severity", "fidelity", "lifecycle", "risk_score",
    "queries", "pseudo_logic", "false_positives", "triage_steps", "tags",
    "test_method", "tuning_guidance",
}

QUERY_KEYS = ("spl", "kql", "aql", "yara_l", "esql", "leql", "crowdstrike", "xql", "lucene", "sumo")


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _require_db(reason):
    if not db_enabled():
        abort(503, description=f"{reason} requires Postgres (DATABASE_URL)")


@app.put("/api/rules/<rule_id>")
def update_rule(rule_id):
    _require_db("rule edits")
    body = request.get_json(silent=True) or {}
    payload = {k: v for k, v in body.items() if k in EDITABLE_RULE_FIELDS}
    if not payload:
        abort(400, description="no editable fields in body")

    if "queries" in payload:
        if not isinstance(payload["queries"], dict):
            abort(400, description="queries must be an object")
        payload["queries"] = {k: v for k, v in payload["queries"].items() if k in QUERY_KEYS}

    with session_scope() as s:
        row = s.query(Rule).filter(Rule.rule_id == rule_id).one_or_none()
        if row is None:
            abort(404)
        for k, v in payload.items():
            setattr(row, k, v)
        row.is_custom = True
        row.last_modified = _today()
        s.flush()
        return jsonify(_row_to_dict(row))


@app.delete("/api/rules/<rule_id>")
def delete_rule(rule_id):
    """Hard-delete a rule and tombstone the rule_id so re-seeds skip it."""
    _require_db("rule deletes")
    user_id = g.get("user_id")
    with session_scope() as s:
        row = s.query(Rule).filter(Rule.rule_id == rule_id).one_or_none()
        if row is None:
            abort(404)
        s.delete(row)
        existing = s.query(DeletedRule).filter(DeletedRule.rule_id == rule_id).one_or_none()
        if existing is None:
            s.add(DeletedRule(
                rule_id=rule_id,
                deleted_by_user_id=user_id,
                deleted_at=_now_iso(),
            ))
        s.flush()
        return jsonify(deleted=rule_id)


@app.post("/api/rules/<rule_id>/duplicate")
def duplicate_rule(rule_id):
    _require_db("rule duplicate")
    with session_scope() as s:
        src = s.query(Rule).filter(Rule.rule_id == rule_id).one_or_none()
        if src is None:
            abort(404)
        base = f"{rule_id}-COPY"
        n = 1
        while s.query(Rule.id).filter(Rule.rule_id == f"{base}-{n}").first():
            n += 1
        new_rid = f"{base}-{n}"
        copy = Rule(
            rule_id=new_rid,
            name=f"{src.name} (Copy)",
            description=src.description,
            tactic=src.tactic, tactic_id=src.tactic_id,
            technique_id=src.technique_id, technique_name=src.technique_name,
            platform=src.platform, data_sources=src.data_sources,
            severity=src.severity, fidelity=src.fidelity, lifecycle="Proposed",
            risk_score=src.risk_score,
            queries=src.queries, pseudo_logic=src.pseudo_logic,
            false_positives=src.false_positives, triage_steps=src.triage_steps,
            tags=src.tags,
            test_method=src.test_method, tuning_guidance=src.tuning_guidance,
            author=src.author,
            created=_today(),
            last_modified=_today(),
            is_custom=True,
        )
        s.add(copy)
        s.flush()
        return jsonify(_row_to_dict(copy)), 201


# ── AI rule builder (Phase 4 — cost-gated) ──────────────────────────────────

AI_DAILY_CAP_USD = float(os.environ.get("AI_DAILY_CAP_USD", "5.00"))


def _ai_spent_today(session, user_id):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rows = session.query(AIUsage.cost_usd).filter(
        AIUsage.user_id == user_id,
        AIUsage.created_at.like(f"{today}%"),
    ).all()
    return sum((r[0] or 0.0) for r in rows)


def _next_custom_rule_id(session):
    base = "TDL-AI"
    n = 1
    while session.query(Rule.id).filter(Rule.rule_id == f"{base}-{n:06d}").first():
        n += 1
    return f"{base}-{n:06d}"


@app.get("/api/ai-usage")
def get_ai_usage():
    user_id = g.get("user_id")
    if not user_id:
        abort(401)
    _require_db("ai usage")
    with session_scope() as s:
        spent = _ai_spent_today(s, user_id)
        return jsonify(
            spent_today_usd=round(spent, 4),
            daily_cap_usd=AI_DAILY_CAP_USD,
            remaining_usd=round(max(0.0, AI_DAILY_CAP_USD - spent), 4),
        )


@app.post("/api/rules/generate")
def generate_rule_endpoint():
    user_id = g.get("user_id")
    if not user_id:
        return jsonify(error="not signed in"), 401
    if not db_enabled():
        return jsonify(error="DATABASE_URL is not set on the server"), 503

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify(error="ANTHROPIC_API_KEY is not set on the server"), 503

    body = request.get_json(silent=True) or {}
    prompt = (body.get("prompt") or "").strip()
    if not prompt:
        return jsonify(error="prompt is required"), 400
    if len(prompt) > 2000:
        return jsonify(error="prompt is too long (max 2000 chars)"), 400

    technique_id = body.get("technique_id") or None
    platforms = body.get("platforms") or None
    primary_siem = body.get("primary_siem") or None
    if platforms is not None and not isinstance(platforms, list):
        return jsonify(error="platforms must be a list"), 400

    with session_scope() as s:
        spent = _ai_spent_today(s, user_id)
        from tools.ai_rule_builder import max_call_cost
        if spent + max_call_cost() > AI_DAILY_CAP_USD:
            return jsonify(
                error="daily AI spend cap reached",
                spent_today_usd=round(spent, 4),
                daily_cap_usd=AI_DAILY_CAP_USD,
            ), 429

    try:
        from tools.ai_rule_builder import generate_rule
        result = generate_rule(
            prompt,
            technique_id=technique_id,
            platforms=platforms,
            primary_siem=primary_siem,
        )
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        return jsonify(error=f"generation failed: {type(e).__name__}: {e}"), 502

    now = datetime.now(timezone.utc).isoformat()
    with session_scope() as s:
        s.add(AIUsage(
            user_id=user_id,
            feature="rule_generate",
            model=result["usage"]["model"],
            input_tokens=result["usage"]["input_tokens"],
            output_tokens=result["usage"]["output_tokens"],
            cost_usd=result["usage"]["cost_usd"],
            created_at=now,
        ))

    return jsonify(rule=result["rule"], usage=result["usage"])


@app.post("/api/rules")
def create_rule():
    user_id = g.get("user_id")
    if not user_id:
        abort(401)
    _require_db("rule creation")

    body = request.get_json(silent=True) or {}
    rule = body.get("rule") or body  # accept either {rule:{...}} or the rule directly
    if not isinstance(rule, dict):
        abort(400, description="rule body must be an object")

    payload = {k: v for k, v in rule.items() if k in EDITABLE_RULE_FIELDS}
    if "queries" in payload and not isinstance(payload["queries"], dict):
        abort(400, description="queries must be an object")
    if "queries" in payload:
        payload["queries"] = {k: v for k, v in payload["queries"].items() if k in QUERY_KEYS}

    with session_scope() as s:
        rule_id = (rule.get("rule_id") or "").strip() or _next_custom_rule_id(s)
        if s.query(Rule.id).filter(Rule.rule_id == rule_id).first():
            abort(409, description=f"rule_id {rule_id} already exists")

        row = Rule(
            rule_id=rule_id,
            name=payload.get("name") or "Untitled rule",
            description=payload.get("description"),
            tactic=payload.get("tactic"), tactic_id=payload.get("tactic_id"),
            technique_id=payload.get("technique_id"), technique_name=payload.get("technique_name"),
            platform=payload.get("platform"), data_sources=payload.get("data_sources"),
            severity=payload.get("severity"), fidelity=payload.get("fidelity"),
            lifecycle=payload.get("lifecycle") or "Proposed",
            risk_score=payload.get("risk_score"),
            queries=payload.get("queries"),
            pseudo_logic=payload.get("pseudo_logic"),
            false_positives=payload.get("false_positives"),
            triage_steps=payload.get("triage_steps"),
            tags=payload.get("tags"),
            test_method=payload.get("test_method"),
            tuning_guidance=payload.get("tuning_guidance"),
            author=rule.get("author") or "AI",
            created=rule.get("created") or _today(),
            last_modified=_today(),
            is_custom=True,
        )
        s.add(row)
        s.flush()

        usage_id = body.get("ai_usage_id")
        if usage_id:
            usage_row = s.query(AIUsage).filter(
                AIUsage.id == usage_id, AIUsage.user_id == user_id
            ).one_or_none()
            if usage_row is not None:
                usage_row.rule_id = row.rule_id

        return jsonify(_row_to_dict(row)), 201


# ── Rule import (Phase 5 — Sigma + 10 SIEM dialects, sync + batch) ──────────

SUPPORTED_SOURCE_TYPES = {"sigma"} | set(QUERY_KEYS)
SYNC_RULE_LIMIT = 50          # ≤50 → sync mode; >50 → batch mode
SYNC_PARALLEL_WORKERS = 4     # concurrent translator calls per sync job


def _job_to_dict(j):
    return {
        "id": j.id,
        "source_type": j.source_type,
        "mode": j.mode,
        "status": j.status,
        "batch_api_id": j.batch_api_id,
        "total_rules": j.total_rules,
        "completed_rules": j.completed_rules,
        "staged_rules": j.staged_rules or [],
        "created_rule_ids": j.created_rule_ids or [],
        "error": j.error,
        "input_tokens": j.input_tokens or 0,
        "output_tokens": j.output_tokens or 0,
        "cost_usd": float(j.cost_usd or 0.0),
        "created_at": j.created_at,
        "completed_at": j.completed_at,
        "applied_at": j.applied_at,
    }


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_source_rules(source_type, content):
    """Return list of source-rule payloads for the translator."""
    from tools.sigma_parser import parse_sigma, parse_dialect_queries
    if source_type == "sigma":
        return [{"kind": "sigma", "rule": r} for r in parse_sigma(content or "")]
    if source_type in QUERY_KEYS:
        return [{"kind": "dialect", "query": q, "dialect": source_type}
                for q in parse_dialect_queries(content or "")]
    raise ValueError(f"unsupported source_type: {source_type!r}")


def _run_sync_job(job_id, sources):
    """Background worker for sync-mode imports.

    Translates each source in parallel (small pool to stay under rate limits),
    appends staged rules to the job row, updates progress as it goes.
    Process restart will leave the job stuck in 'running' — operationally
    acceptable for MVP; user can retry.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from tools.ai_rule_translator import translate_sigma_rule, translate_dialect_query

    def translate_one(src):
        if src["kind"] == "sigma":
            return translate_sigma_rule(src["rule"])
        return translate_dialect_query(src["query"], src["dialect"])

    staged, total_in, total_out, total_cost = [], 0, 0, 0.0
    failures = []

    with ThreadPoolExecutor(max_workers=SYNC_PARALLEL_WORKERS) as ex:
        futures = {ex.submit(translate_one, s): i for i, s in enumerate(sources)}
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                result = fut.result()
                staged.append(result["rule"])
                total_in += result["usage"]["input_tokens"]
                total_out += result["usage"]["output_tokens"]
                total_cost += result["usage"]["cost_usd"]
            except Exception as e:
                failures.append({"index": idx, "error": f"{type(e).__name__}: {e}"})

            # checkpoint after each completion so the UI can poll progress
            with session_scope() as s:
                row = s.query(ImportJob).filter(ImportJob.id == job_id).one_or_none()
                if row is None:
                    return
                row.staged_rules = staged
                row.completed_rules = len(staged) + len(failures)
                row.input_tokens = total_in
                row.output_tokens = total_out
                row.cost_usd = round(total_cost, 6)

    with session_scope() as s:
        row = s.query(ImportJob).filter(ImportJob.id == job_id).one_or_none()
        if row is None:
            return
        row.staged_rules = staged
        row.input_tokens = total_in
        row.output_tokens = total_out
        row.cost_usd = round(total_cost, 6)
        row.completed_at = _now_iso()
        if not staged:
            row.status = "failed"
            row.error = f"all {len(sources)} translations failed: " + json.dumps(failures[:3])
        else:
            row.status = "awaiting_review"
            if failures:
                row.error = f"{len(failures)}/{len(sources)} failed; review staged rules"


@app.post("/api/rules/import")
def create_import_job():
    user_id = g.get("user_id")
    if not user_id:
        return jsonify(error="not signed in"), 401
    if not db_enabled():
        return jsonify(error="DATABASE_URL is not set on the server"), 503
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify(error="ANTHROPIC_API_KEY is not set on the server"), 503

    body = request.get_json(silent=True) or {}
    source_type = (body.get("source_type") or "").strip()
    content = body.get("content") or ""
    if source_type not in SUPPORTED_SOURCE_TYPES:
        return jsonify(error=f"source_type must be one of: {sorted(SUPPORTED_SOURCE_TYPES)}"), 400
    if not content.strip():
        return jsonify(error="content is required"), 400

    try:
        sources = _parse_source_rules(source_type, content)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    if not sources:
        return jsonify(error="no rules found in content"), 400

    n = len(sources)
    mode = "sync" if n <= SYNC_RULE_LIMIT else "batch"

    # Cost ceiling check using Phase 4 daily cap
    from tools.ai_rule_builder import max_call_cost
    estimated_max = max_call_cost() * n
    with session_scope() as s:
        spent = _ai_spent_today(s, user_id)
        if spent + estimated_max > AI_DAILY_CAP_USD:
            return jsonify(
                error=f"this import would exceed today's spend cap (would need ~${estimated_max:.2f}, only ${max(0, AI_DAILY_CAP_USD - spent):.2f} left)",
                rules_in_request=n,
            ), 429

        job = ImportJob(
            user_id=user_id,
            source_type=source_type,
            mode=mode,
            status="running" if mode == "sync" else "pending",
            total_rules=n,
            completed_rules=0,
            staged_rules=[],
            created_at=_now_iso(),
        )
        s.add(job)
        s.flush()
        job_id = job.id
        job_payload = _job_to_dict(job)

    if mode == "sync":
        import threading
        threading.Thread(target=_run_sync_job, args=(job_id, sources), daemon=True).start()
    else:
        # Batch mode wired separately in the next commit; for now reject so
        # frontend doesn't see a job that never makes progress.
        with session_scope() as s:
            row = s.query(ImportJob).filter(ImportJob.id == job_id).one_or_none()
            if row is not None:
                row.status = "failed"
                row.error = "batch mode not yet implemented; cap requests at 50 rules"
        return jsonify(error="batch mode not yet wired up; please cap input at 50 rules for now"), 501

    return jsonify(job_payload), 202


@app.get("/api/import-jobs")
def list_import_jobs():
    user_id = g.get("user_id")
    if not user_id:
        return jsonify(error="not signed in"), 401
    if not db_enabled():
        return jsonify(error="DATABASE_URL is not set on the server"), 503
    with session_scope() as s:
        rows = (s.query(ImportJob)
                  .filter(ImportJob.user_id == user_id)
                  .order_by(ImportJob.id.desc())
                  .limit(50)
                  .all())
        return jsonify([_job_to_dict(r) for r in rows])


@app.get("/api/import-jobs/<int:job_id>")
def get_import_job(job_id):
    user_id = g.get("user_id")
    if not user_id:
        return jsonify(error="not signed in"), 401
    if not db_enabled():
        return jsonify(error="DATABASE_URL is not set on the server"), 503
    with session_scope() as s:
        row = s.query(ImportJob).filter(
            ImportJob.id == job_id, ImportJob.user_id == user_id
        ).one_or_none()
        if row is None:
            return jsonify(error="not found"), 404
        return jsonify(_job_to_dict(row))


@app.post("/api/import-jobs/<int:job_id>/apply")
def apply_import_job(job_id):
    """Save the staged rules from a completed import to the library.

    Body may include {selected_indexes: [0, 2, 4]} to apply a subset; default
    is apply all.
    """
    user_id = g.get("user_id")
    if not user_id:
        return jsonify(error="not signed in"), 401
    if not db_enabled():
        return jsonify(error="DATABASE_URL is not set on the server"), 503

    body = request.get_json(silent=True) or {}
    selected = body.get("selected_indexes")

    with session_scope() as s:
        job = s.query(ImportJob).filter(
            ImportJob.id == job_id, ImportJob.user_id == user_id
        ).one_or_none()
        if job is None:
            return jsonify(error="not found"), 404
        if job.status != "awaiting_review":
            return jsonify(error=f"job status is {job.status!r}, must be 'awaiting_review' to apply"), 409

        staged = list(job.staged_rules or [])
        if selected is not None:
            if not isinstance(selected, list) or any(not isinstance(i, int) for i in selected):
                return jsonify(error="selected_indexes must be a list of ints"), 400
            staged = [staged[i] for i in selected if 0 <= i < len(staged)]

        if not staged:
            return jsonify(error="no staged rules to apply"), 400

        created_ids = []
        for rule in staged:
            rule_id = (rule.get("rule_id") or "").strip() or _next_custom_rule_id(s)
            if s.query(Rule.id).filter(Rule.rule_id == rule_id).first():
                rule_id = _next_custom_rule_id(s)

            payload = {k: v for k, v in rule.items() if k in EDITABLE_RULE_FIELDS}
            if "queries" in payload and isinstance(payload["queries"], dict):
                payload["queries"] = {k: v for k, v in payload["queries"].items() if k in QUERY_KEYS}

            row = Rule(
                rule_id=rule_id,
                name=payload.get("name") or "Untitled imported rule",
                description=payload.get("description"),
                tactic=payload.get("tactic"), tactic_id=payload.get("tactic_id"),
                technique_id=payload.get("technique_id"), technique_name=payload.get("technique_name"),
                platform=payload.get("platform"), data_sources=payload.get("data_sources"),
                severity=payload.get("severity"), fidelity=payload.get("fidelity"),
                lifecycle=payload.get("lifecycle") or "Proposed",
                risk_score=payload.get("risk_score"),
                queries=payload.get("queries"),
                pseudo_logic=payload.get("pseudo_logic"),
                false_positives=payload.get("false_positives"),
                triage_steps=payload.get("triage_steps"),
                tags=payload.get("tags"),
                test_method=payload.get("test_method"),
                tuning_guidance=payload.get("tuning_guidance"),
                author=rule.get("author") or "AI (imported)",
                created=rule.get("created") or _today(),
                last_modified=_today(),
                is_custom=True,
            )
            s.add(row)
            s.flush()
            created_ids.append(row.rule_id)

        # Aggregate translator usage into ai_usage as a single import row.
        if job.input_tokens or job.output_tokens:
            s.add(AIUsage(
                user_id=user_id,
                feature=f"{job.source_type}_import",
                model=os.environ.get("AI_BUILDER_MODEL", "claude-sonnet-4-6"),
                input_tokens=job.input_tokens or 0,
                output_tokens=job.output_tokens or 0,
                cost_usd=float(job.cost_usd or 0.0),
                created_at=_now_iso(),
            ))

        job.created_rule_ids = created_ids
        job.status = "applied"
        job.applied_at = _now_iso()
        s.flush()
        return jsonify(_job_to_dict(job))


def _load_full_rules():
    """Full rule dicts including pseudo_logic + all SIEM queries.

    DB-backed when DATABASE_URL is set (forward-compatible with Phase 3
    edits); falls back to reading source YAML files in rules/.
    """
    import yaml
    if db_enabled():
        with session_scope() as s:
            rows = s.query(Rule).order_by(Rule.rule_id).all()
            return [_row_to_dict(r) for r in rows]
    out = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if isinstance(doc, dict):
            out.append(doc)
    return out


@app.get("/api/rules/export")
def rules_export():
    fmt = (request.args.get("format") or "yaml").lower()
    if fmt != "yaml":
        abort(400, description="format must be: yaml")

    import yaml

    rules = _load_full_rules()

    tactic = request.args.get("tactic")
    severity = request.args.get("severity")
    lifecycle = request.args.get("lifecycle")
    q = (request.args.get("q") or "").lower().strip()

    if tactic and tactic != "All":
        rules = [r for r in rules if r.get("tactic") == tactic]
    if severity and severity != "All":
        rules = [r for r in rules if r.get("severity") == severity]
    if lifecycle and lifecycle != "All":
        rules = [r for r in rules if r.get("lifecycle") == lifecycle]
    if q:
        def _matches(r):
            return (
                q in (r.get("name") or "").lower()
                or q in (r.get("rule_id") or "").lower()
                or q in (r.get("technique_id") or "").lower()
                or any(q in (t or "").lower() for t in (r.get("tags") or []))
            )
        rules = [r for r in rules if _matches(r)]

    if not rules:
        abort(404, description="no rules match the supplied filters")

    drop_keys = {"org_id", "is_custom"}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in rules:
            payload = {
                k: v for k, v in r.items()
                if k not in drop_keys and v is not None and v != ""
            }
            tactic_slug = (r.get("tactic") or "uncategorized").lower().replace(" ", "-")
            arcname = f"rules/{tactic_slug}/{r['rule_id']}.yaml"
            zf.writestr(
                arcname,
                yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
            )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    filtered = bool(tactic or severity or lifecycle or q)
    suffix = f"-filtered-{len(rules)}" if filtered else f"-all-{len(rules)}"
    filename = f"tdl-rules{suffix}-{stamp}.zip"
    return Response(
        buf.getvalue(),
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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


@app.get("/api/coverage/export")
def coverage_export():
    fmt = (request.args.get("format") or "json").lower()
    if fmt not in ("json", "csv", "pdf"):
        abort(400, description="format must be one of: json, csv, pdf")

    p = MATRIX / "coverage_report.json"
    if not p.exists():
        subprocess.run(["node", str(ROOT / "tools" / "coverage.js")], check=True, cwd=ROOT)
    with p.open("r", encoding="utf-8") as f:
        report = json.load(f)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    base = f"tdl-coverage-{stamp}"

    if fmt == "json":
        body = json.dumps(report, indent=2)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{base}.json"'},
        )

    if fmt == "csv":
        return Response(
            _coverage_csv(report),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{base}.csv"'},
        )

    return Response(
        _coverage_pdf(report),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{base}.pdf"'},
    )


def _coverage_csv(report):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["section", "key", "metric", "value"])

    summary = report.get("summary", {}) or {}
    for k, v in summary.items():
        w.writerow(["summary", "", k, v])

    by_tactic = report.get("by_tactic", {}) or {}
    for tactic, stats in by_tactic.items():
        for k, v in (stats or {}).items():
            w.writerow(["by_tactic", tactic, k, v])

    buf.write("\n")
    w.writerow(["technique_id", "technique_name", "tactic", "rule_count", "rules"])
    for t in report.get("by_technique", []) or []:
        w.writerow([
            t.get("technique_id", ""),
            t.get("technique_name", ""),
            t.get("tactic", ""),
            t.get("rule_count", 0),
            ";".join(t.get("rules", []) or []),
        ])
    return buf.getvalue()


def _coverage_pdf(report):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        title="TDL Playbook · Coverage Report",
    )
    styles = getSampleStyleSheet()
    story = []

    summary = report.get("summary", {}) or {}
    generated = report.get("generated_at") or datetime.now(timezone.utc).isoformat()

    story.append(Paragraph("TDL Playbook — Coverage Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {generated}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Summary", styles["Heading2"]))
    sum_rows = [["Metric", "Value"]] + [[k, str(v)] for k, v in summary.items()]
    sum_tbl = Table(sum_rows, hAlign="LEFT", colWidths=[2.5 * inch, 1.5 * inch])
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(sum_tbl)
    story.append(Spacer(1, 18))

    story.append(Paragraph("Coverage by Tactic", styles["Heading2"]))
    tac_rows = [["Tactic", "Total", "Deployed", "Proposed", "Unique Techniques"]]
    for tactic, s in (report.get("by_tactic", {}) or {}).items():
        s = s or {}
        tac_rows.append([
            tactic,
            str(s.get("total", 0)),
            str(s.get("deployed", 0)),
            str(s.get("proposed", 0)),
            str(s.get("unique_techniques", 0)),
        ])
    tac_tbl = Table(tac_rows, hAlign="LEFT", repeatRows=1)
    tac_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(tac_tbl)
    story.append(PageBreak())

    story.append(Paragraph("Coverage by Technique", styles["Heading2"]))
    story.append(Paragraph(
        "One row per ATT&CK technique with at least one rule. "
        "Rule count reflects the current TDL library.",
        styles["Italic"],
    ))
    story.append(Spacer(1, 6))
    tech_rows = [["Technique ID", "Name", "Tactic", "Rules"]]
    for t in report.get("by_technique", []) or []:
        tech_rows.append([
            t.get("technique_id", ""),
            t.get("technique_name", ""),
            t.get("tactic", ""),
            str(t.get("rule_count", 0)),
        ])
    tech_tbl = Table(
        tech_rows, hAlign="LEFT", repeatRows=1,
        colWidths=[1.0 * inch, 2.6 * inch, 2.0 * inch, 0.7 * inch],
    )
    tech_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ALIGN", (3, 1), (3, -1), "RIGHT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(tech_tbl)

    doc.build(story)
    return buf.getvalue()


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


# ── Org profile (Postgres-backed; Phase 3.5) ────────────────────────────────

def _org_to_dict(row):
    return {
        "user_id": row.user_id,
        "org_name": row.org_name,
        "primary_siem": row.primary_siem,
        "log_sources_deployed": row.log_sources_deployed or [],
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


@app.get("/api/org-profile")
def get_org_profile():
    user_id = g.get("user_id")
    if not user_id:
        abort(401)
    _require_db("org profile")
    with session_scope() as s:
        row = s.query(OrgProfile).filter(OrgProfile.user_id == user_id).one_or_none()
        if row is None:
            return jsonify(None)
        return jsonify(_org_to_dict(row))


@app.put("/api/org-profile")
def put_org_profile():
    user_id = g.get("user_id")
    if not user_id:
        abort(401)
    _require_db("org profile")
    body = request.get_json(silent=True) or {}
    org_name = (body.get("org_name") or "").strip()
    if not org_name:
        abort(400, description="org_name required")
    primary_siem = body.get("primary_siem") or None
    log_sources = body.get("log_sources_deployed") or []
    if not isinstance(log_sources, list):
        abort(400, description="log_sources_deployed must be a list")

    now = datetime.now(timezone.utc).isoformat()
    with session_scope() as s:
        row = s.query(OrgProfile).filter(OrgProfile.user_id == user_id).one_or_none()
        if row is None:
            row = OrgProfile(user_id=user_id, created_at=now)
            s.add(row)
        row.org_name = org_name
        row.primary_siem = primary_siem
        row.log_sources_deployed = log_sources
        row.updated_at = now
        s.flush()
        return jsonify(_org_to_dict(row))


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
