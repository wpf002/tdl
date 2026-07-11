#!/usr/bin/env python3
"""Migration: create the rule_edits table for per-account rule overrides (#7).

Rule edits are stored per user and overlaid on the shared rule at read time, so
one account's edits never mutate the shared library or leak to other accounts.
Idempotent (create_all is a no-op if the table exists); no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_add_rule_edits
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
    Base.metadata.create_all(engine)  # creates rule_edits if missing
    print("Migration complete: rule_edits table ensured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
