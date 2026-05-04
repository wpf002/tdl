"""SQLAlchemy ORM models for TDL Playbook."""

from sqlalchemy import Boolean, Column, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from tools.db import Base


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

    user_id = Column(String(64), primary_key=True)  # Clerk user id
    org_name = Column(String(255), nullable=False)
    primary_siem = Column(String(32))
    log_sources_deployed = Column(JSONB)  # list[str]
    created_at = Column(String(32))
    updated_at = Column(String(32))
