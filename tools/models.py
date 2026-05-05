"""SQLAlchemy ORM models for TDL Playbook."""

from sqlalchemy import Boolean, Column, Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from tools.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)  # uuid4 hex
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    email_verified = Column(Boolean, nullable=False, default=False, server_default="false")
    created_at = Column(String(32), nullable=False)
    last_login_at = Column(String(32), nullable=True)


class AuthToken(Base):
    """One-time tokens for email verification and password reset.

    `token_hash` is sha256(plaintext) — the plaintext is only sent in email
    and never persisted. `purpose` is 'verify_email' or 'reset_password'.
    """
    __tablename__ = "auth_tokens"

    token_hash = Column(String(64), primary_key=True)
    user_id = Column(String(64), nullable=False, index=True)
    purpose = Column(String(32), nullable=False)
    created_at = Column(String(32), nullable=False)
    expires_at = Column(String(32), nullable=False)
    used_at = Column(String(32), nullable=True)


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True)
    rule_id = Column(String(64), unique=True, nullable=False, index=True)

    name = Column(String(255), nullable=False)
    description = Column(Text)

    tactic = Column(String(64), index=True)
    tactic_id = Column(String(16))
    technique_id = Column(String(32), index=True)
    technique_name = Column(String(255))

    platform = Column(JSONB)
    data_sources = Column(JSONB)

    severity = Column(String(16), index=True)
    fidelity = Column(String(16))
    lifecycle = Column(String(32), index=True)

    risk_score = Column(Integer)

    queries = Column(JSONB)
    pseudo_logic = Column(Text)
    false_positives = Column(JSONB)
    triage_steps = Column(JSONB)
    tags = Column(JSONB)

    test_method = Column(String(64))
    tuning_guidance = Column(Text)

    author = Column(String(128))
    created = Column(String(32))
    last_modified = Column(String(32))

    org_id = Column(String(64), index=True, nullable=True)
    is_custom = Column(Boolean, nullable=False, default=False, server_default="false")


Index("ix_rules_org_lifecycle", Rule.org_id, Rule.lifecycle)


class OrgProfile(Base):
    __tablename__ = "org_profiles"

    user_id = Column(String(64), primary_key=True)
    org_name = Column(String(255), nullable=False)
    primary_siem = Column(String(32))
    log_sources_deployed = Column(JSONB)  # list[str]
    created_at = Column(String(32))
    updated_at = Column(String(32))


class AIUsage(Base):
    __tablename__ = "ai_usage"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), index=True, nullable=False)
    org_id = Column(String(64), index=True, nullable=True)
    feature = Column(String(32), index=True, nullable=False)  # 'rule_generate', 'sigma_import', etc.
    model = Column(String(64), nullable=False)
    input_tokens = Column(Integer, nullable=False, default=0)
    output_tokens = Column(Integer, nullable=False, default=0)
    cost_usd = Column(Float, nullable=False, default=0.0)
    rule_id = Column(String(64), nullable=True)  # set if a rule was saved from this call
    created_at = Column(String(32), index=True, nullable=False)


Index("ix_ai_usage_user_day", AIUsage.user_id, AIUsage.created_at)


class DeletedRule(Base):
    """Tombstone for hard-deleted rules.

    Hard-deleting a rule removes the row from `rules`, but the YAML file may
    still be on disk under `rules/`. The seeder consults this table and skips
    any rule_id present here, so the deletion survives re-seeds.
    """
    __tablename__ = "deleted_rules"

    rule_id = Column(String(64), primary_key=True)
    deleted_by_user_id = Column(String(64), nullable=True)
    deleted_at = Column(String(32), nullable=False)


class ImportJob(Base):
    """Phase 5 — rule-import job (Sigma YAML or SIEM-dialect query → TDL rule).

    Status state machine:
        running          → translator threads/batch are processing
        awaiting_review  → translation done, staged_rules populated, user can review + apply
        applied          → user applied the import; created_rule_ids populated
        failed           → terminal failure; check `error`
    """
    __tablename__ = "import_jobs"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), index=True, nullable=False)
    org_id = Column(String(64), nullable=True)
    source_type = Column(String(32), nullable=False)  # 'sigma' | 'spl' | 'kql' | 'aql' | 'yara_l' | 'esql' | 'leql' | 'crowdstrike' | 'xql' | 'lucene' | 'sumo'
    mode = Column(String(16), nullable=False)  # 'sync' | 'batch'
    status = Column(String(16), index=True, nullable=False)
    batch_api_id = Column(String(64), nullable=True)
    total_rules = Column(Integer, nullable=False, default=0)
    completed_rules = Column(Integer, nullable=False, default=0)
    staged_rules = Column(JSONB)            # list[dict] — translated TDL rules, awaiting review
    created_rule_ids = Column(JSONB)        # list[str] — saved rule_ids after apply
    error = Column(Text)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    cost_usd = Column(Float, default=0.0)
    created_at = Column(String(32), nullable=False)
    completed_at = Column(String(32))
    applied_at = Column(String(32))
