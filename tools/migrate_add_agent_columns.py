#!/usr/bin/env python3
"""Migration: add the per-agent `language` column to ai_usage.

Idempotent — uses ADD COLUMN IF NOT EXISTS. Lets the orchestrator attribute
each specialist-agent Claude call to its SIEM language. Safe on every deploy;
no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_add_agent_columns
"""

import sys

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text

from tools.db import Base, db_enabled, get_engine
from tools import models  # noqa: F401  (registers tables on Base.metadata)


def main():
    if not db_enabled():
        print("DATABASE_URL not set — skipping migration.")
        return 0

    engine = get_engine()
    # Ensure any brand-new tables exist.
    Base.metadata.create_all(engine)

    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE ai_usage ADD COLUMN IF NOT EXISTS language VARCHAR(32)"
        ))
    print("Migration complete: ai_usage.language ensured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
