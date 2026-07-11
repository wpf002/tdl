#!/usr/bin/env python3
"""Migration: per-account delete + duplicate scoping (#7).

Adds:
  - rules.owner_user_id   — NULL = shared library rule; set = a user's private
                            duplicate, visible only to its owner.
  - rule_edits.deleted    — per-account soft delete of a shared rule.

Idempotent (ADD COLUMN IF NOT EXISTS); no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_add_rule_ownership
"""

import sys

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text

from tools.db import Base, db_enabled, get_engine
from tools import models  # noqa: F401


def main():
    if not db_enabled():
        print("DATABASE_URL not set — skipping migration.")
        return 0
    engine = get_engine()
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE rules ADD COLUMN IF NOT EXISTS owner_user_id VARCHAR(64)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_rules_owner_user_id ON rules (owner_user_id)"))
        conn.execute(text("ALTER TABLE rule_edits ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false"))
    print("Migration complete: rules.owner_user_id + rule_edits.deleted ensured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
