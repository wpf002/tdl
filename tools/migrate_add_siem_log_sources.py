#!/usr/bin/env python3
"""Migration: add org_profiles.siem_log_sources for per-SIEM log sources (#15).

Onboarding can now select log sources per SIEM/query language. The union of all
per-SIEM sources is still mirrored into the existing log_sources_deployed column
so coverage/matrix/recommend keep working unchanged. Backfill wraps each existing
flat log_sources_deployed under the org's primary query language.
Idempotent; no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_add_siem_log_sources
"""

import json
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
            "ALTER TABLE org_profiles ADD COLUMN IF NOT EXISTS siem_log_sources JSONB"
        ))
        rows = conn.execute(text(
            "SELECT user_id, primary_query_language, primary_siem, log_sources_deployed "
            "FROM org_profiles WHERE siem_log_sources IS NULL"
        )).fetchall()
        for user_id, pql, siem, ls in rows:
            lang = pql or siem
            mapping = {lang: (ls or [])} if lang else {}
            conn.execute(
                text("UPDATE org_profiles SET siem_log_sources = CAST(:v AS JSONB) WHERE user_id = :u"),
                {"v": json.dumps(mapping), "u": user_id},
            )
    print(f"Migration complete: siem_log_sources ensured, backfilled {len(rows)} row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
