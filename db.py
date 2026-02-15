from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, RowMapping


def get_engine() -> Engine:
    """
    If DATABASE_URL is set -> uses Postgres (recommended for real app).
    Else -> uses local SQLite for dev.
    """
    db_url = os.getenv("DATABASE_URL", "").strip()
    if not db_url:
        db_url = "sqlite:///maptrix.db"
    return create_engine(db_url, pool_pre_ping=True)


def exec_sql(engine: Engine, sql: str, params: Optional[dict] = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(sql), params or {})


def fetch_all(engine: Engine, sql: str, params: Optional[dict] = None) -> List[RowMapping]:
    with engine.begin() as conn:
        res = conn.execute(text(sql), params or {})
        return [r._mapping for r in res.fetchall()]


def fetch_one(engine: Engine, sql: str, params: Optional[dict] = None) -> Optional[RowMapping]:
    rows = fetch_all(engine, sql, params)
    return rows[0] if rows else None