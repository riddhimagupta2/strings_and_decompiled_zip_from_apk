import sqlite3
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.models import Base

DATABASE_URL = "sqlite:///./storage/apk_extractor.db"
DB_PATH = Path("storage/apk_extractor.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _migrate_columns():
    Path("storage").mkdir(exist_ok=True)
    if not DB_PATH.exists():
        return
    conn = sqlite3.connect(DB_PATH)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(analysis_jobs)")}
        if "progress_percent" not in cols:
            conn.execute(
                "ALTER TABLE analysis_jobs ADD COLUMN progress_percent INTEGER NOT NULL DEFAULT 0"
            )
        if "progress_label" not in cols:
            conn.execute(
                "ALTER TABLE analysis_jobs ADD COLUMN progress_label VARCHAR DEFAULT 'Queued for analysis'"
            )
        conn.commit()
    finally:
        conn.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
