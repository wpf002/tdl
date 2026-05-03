#!/usr/bin/env python3
"""Create the TDL Playbook database schema.

Idempotent: uses CREATE TABLE IF NOT EXISTS via SQLAlchemy metadata. Safe to
run on every deploy. No-op if DATABASE_URL is unset (so local dev without
Postgres just works).
"""

import sys

from dotenv import load_dotenv
load_dotenv()

from tools.db import Base, db_enabled, get_engine
from tools import models  # noqa: F401  (registers tables on Base.metadata)


def main():
    if not db_enabled():
        print("DATABASE_URL not set — skipping migration.")
        return 0
    engine = get_engine()
    Base.metadata.create_all(engine)
    print(f"Migration complete. Tables: {sorted(Base.metadata.tables.keys())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
