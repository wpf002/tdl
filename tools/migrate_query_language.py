#!/usr/bin/env python3
"""Migration: add org_profiles.primary_query_language and backfill from primary_siem.

The legacy `primary_siem` column already stored query-language keys (spl, kql,
…), so the backfill is a straight copy with a defensive map for any SIEM-style
display values that may have been stored. Idempotent; no-op without DATABASE_URL.

Usage:
    python -m tools.migrate_query_language
"""

import sys

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text

from tools.db import Base, db_enabled, get_engine
from tools import models  # noqa: F401  (registers tables on Base.metadata)

# Map any legacy SIEM-style values to the canonical query-language key.
LEGACY_SIEM_TO_LANG = {
    "splunk": "spl", "spl": "spl",
    "sentinel": "kql", "defender": "kql", "microsoft": "kql", "kql": "kql",
    "qradar": "aql", "aql": "aql",
    "chronicle": "yara_l", "yara_l": "yara_l", "yara-l": "yara_l",
    "elastic": "esql", "elasticsearch": "esql", "esql": "esql",
    "rapid7": "leql", "insightidr": "leql", "leql": "leql",
    "crowdstrike": "crowdstrike", "falcon": "crowdstrike", "logscale": "crowdstrike", "cql": "crowdstrike",
    "xsiam": "xql", "cortex": "xql", "xql": "xql",
    "lucene": "lucene", "opensearch": "lucene", "graylog": "lucene", "exabeam": "lucene",
    "sumo": "sumo", "sumologic": "sumo", "sumo logic": "sumo",
}


def main():
    if not db_enabled():
        print("DATABASE_URL not set — skipping migration.")
        return 0

    engine = get_engine()
    Base.metadata.create_all(engine)

    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE org_profiles ADD COLUMN IF NOT EXISTS primary_query_language VARCHAR(32)"
        ))
        rows = conn.execute(text(
            "SELECT user_id, primary_siem FROM org_profiles "
            "WHERE primary_query_language IS NULL AND primary_siem IS NOT NULL"
        )).fetchall()
        for user_id, siem in rows:
            key = LEGACY_SIEM_TO_LANG.get((siem or "").strip().lower(), (siem or "").strip().lower() or None)
            conn.execute(
                text("UPDATE org_profiles SET primary_query_language = :k WHERE user_id = :u"),
                {"k": key, "u": user_id},
            )
    print(f"Migration complete: primary_query_language ensured, backfilled {len(rows)} row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
