#!/usr/bin/env python3
"""One-time migration: switch from Clerk auth to local users.

What this does (idempotent):
  1. Creates the new `users` and `auth_tokens` tables.
  2. Wipes Clerk-keyed rows from `org_profiles`, `ai_usage`, and
     `import_jobs` so the single existing user re-onboards fresh.

Safe to run more than once. After this, you register a new account through
the app and re-enter your org profile.

Usage:
    python -m tools.migrate_drop_clerk
"""

import sys

from dotenv import load_dotenv
load_dotenv()

from tools.db import Base, db_enabled, get_engine, session_scope
from tools.models import AIUsage, ImportJob, OrgProfile  # noqa: F401  (registers tables)
from tools import models  # noqa: F401  (ensures User + AuthToken tables registered)


def main():
    if not db_enabled():
        print("DATABASE_URL not set — nothing to do.")
        return 0

    engine = get_engine()
    Base.metadata.create_all(engine)
    print(f"Schema synced. Tables: {sorted(Base.metadata.tables.keys())}")

    with session_scope() as s:
        deleted = {}
        deleted["org_profiles"] = s.query(OrgProfile).delete()
        deleted["ai_usage"] = s.query(AIUsage).delete()
        deleted["import_jobs"] = s.query(ImportJob).delete()
    for table, n in deleted.items():
        print(f"  cleared {table}: {n} rows")

    print("Done. Register a new account in the app to re-onboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
