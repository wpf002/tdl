#!/usr/bin/env python3
"""Migration: add the rules.requirements JSONB column.

Holds {log_sources: [{source, events: [{id, name, required}]}]}. Idempotent;
no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_add_requirements
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
    Base.metadata.create_all(engine)

    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE rules ADD COLUMN IF NOT EXISTS requirements JSONB"
        ))
    print("Migration complete: rules.requirements ensured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
