"""SQLAlchemy engine + session factory.

Reads DATABASE_URL from env. If unset, the rest of the app should fall back to
the rules.json file so local dev keeps working without Postgres.

Railway exposes DATABASE_URL with the postgres:// scheme; SQLAlchemy 2.x wants
postgresql://, so we normalize on read.
"""

import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


def database_url():
    url = os.environ.get("DATABASE_URL", "")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url


_engine = None
_SessionLocal = None
Base = declarative_base()


def get_engine():
    global _engine
    if _engine is None:
        url = database_url()
        if not url:
            raise RuntimeError("DATABASE_URL is not set")
        _engine = create_engine(url, pool_pre_ping=True, future=True)
    return _engine


def get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _SessionLocal


@contextmanager
def session_scope():
    s = get_session_factory()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def db_enabled():
    return bool(database_url())
