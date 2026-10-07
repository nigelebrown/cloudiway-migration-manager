import sqlite3
from contextlib import contextmanager
from app.config import settings

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, is_secret INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_email TEXT NOT NULL UNIQUE,
  target_email TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  generated_password_enc TEXT,
  rackspace_status TEXT NOT NULL DEFAULT 'pending',
  cloudiway_status TEXT NOT NULL DEFAULT 'not_submitted',
  cloudiway_object_id INTEGER,
  migration_status TEXT NOT NULL DEFAULT 'waiting',
  error_message TEXT,
  batch_number INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

@contextmanager
def conn():
    db=sqlite3.connect(settings.database_path, check_same_thread=False)
    db.row_factory=sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()

def init_db():
    with conn() as db: db.executescript(SCHEMA)

def set_setting(key:str,value:str,is_secret:bool=False):
    with conn() as db:
        db.execute("""INSERT INTO settings(key,value,is_secret) VALUES(?,?,?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value,is_secret=excluded.is_secret""",
        (key,value,1 if is_secret else 0))

def get_setting(key:str)->str|None:
    with conn() as db:
        row=db.execute("SELECT value FROM settings WHERE key=?",(key,)).fetchone()
        return row["value"] if row else None

def log_event(user_id:int|None,event_type:str,message:str):
    with conn() as db:
        db.execute("INSERT INTO events(user_id,event_type,message) VALUES(?,?,?)",
                   (user_id,event_type,message[:2000]))
