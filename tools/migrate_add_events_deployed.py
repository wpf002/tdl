#!/usr/bin/env python3
"""Migration: add org_profiles.events_deployed JSONB column.

Granular per-event-ID inventory of what each org actually collects, keyed by
log source id. Drives the event-level MITRE matrix dimming and the
'Missing: 4769' coverage indicator on rules.

Idempotent; no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_add_events_deployed
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
        conn.execute(text(
            "ALTER TABLE org_profiles ADD COLUMN IF NOT EXISTS events_deployed JSONB"
        ))
    print("Migration complete: org_profiles.events_deployed ensured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
