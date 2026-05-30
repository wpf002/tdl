#!/usr/bin/env python3
"""Migration: add org_profiles.query_languages and backfill from the single
primary_query_language / primary_siem value.

Orgs previously selected one query language; this adds a multi-select list.
Existing rows are backfilled by wrapping their single language into a one-element
list. Idempotent; no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_add_query_languages
"""

import json
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
            "ALTER TABLE org_profiles ADD COLUMN IF NOT EXISTS query_languages JSONB"
        ))
        rows = conn.execute(text(
            "SELECT user_id, primary_query_language, primary_siem FROM org_profiles "
            "WHERE query_languages IS NULL"
        )).fetchall()
        for user_id, pql, siem in rows:
            single = pql or siem
            langs = [single] if single else []
            conn.execute(
                text("UPDATE org_profiles SET query_languages = CAST(:v AS JSONB) WHERE user_id = :u"),
                {"v": json.dumps(langs), "u": user_id},
            )
    print(f"Migration complete: query_languages ensured, backfilled {len(rows)} row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
