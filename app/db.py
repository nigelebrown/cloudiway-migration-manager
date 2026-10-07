import time
from contextlib import contextmanager

import pymysql
from pymysql.cursors import DictCursor

from app.config import settings


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS settings (
        `key` VARCHAR(191) PRIMARY KEY,
        `value` LONGTEXT NOT NULL,
        is_secret TINYINT(1) NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id BIGINT PRIMARY KEY AUTO_INCREMENT,
        source_email VARCHAR(320) NOT NULL UNIQUE,
        target_email VARCHAR(320) NOT NULL,
        first_name VARCHAR(255) NULL,
        last_name VARCHAR(255) NULL,
        computer_number VARCHAR(64) NULL,
        generated_password_enc LONGTEXT NULL,
        password_reset_method VARCHAR(32) NOT NULL DEFAULT 'automatic',
        manual_password_generated_at DATETIME NULL,
        manual_password_confirmed_at DATETIME NULL,
        rackspace_status VARCHAR(64) NOT NULL DEFAULT 'pending',
        cloudiway_status VARCHAR(128) NOT NULL DEFAULT 'not_submitted',
        cloudiway_object_id BIGINT NULL,
        migration_status VARCHAR(64) NOT NULL DEFAULT 'waiting',
        progress_percent DOUBLE NULL,
        progress_detail LONGTEXT NULL,
        error_message LONGTEXT NULL,
        batch_number INT NULL,
        batch_started_at DATETIME NULL,
        attempt_count INT NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_users_migration_status (migration_status),
        INDEX idx_users_batch_number (batch_number),
        INDEX idx_users_cloudiway_object_id (cloudiway_object_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        id BIGINT PRIMARY KEY AUTO_INCREMENT,
        user_id BIGINT NULL,
        event_type VARCHAR(128) NOT NULL,
        message LONGTEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_events_user_id (user_id),
        INDEX idx_events_created_at (created_at),
        CONSTRAINT fk_events_user
            FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS runtime (
        `key` VARCHAR(191) PRIMARY KEY,
        `value` LONGTEXT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
]


class DBSession:
    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def _convert_sql(sql: str) -> str:
        # The application historically used sqlite-style '?' parameters.
        # Keep that call surface while sending MySQL-compatible '%s' markers.
        return sql.replace("?", "%s")

    def execute(self, sql: str, params=()):
        cursor = self.connection.cursor()
        cursor.execute(self._convert_sql(sql), params or ())
        return cursor


def _connect():
    return pymysql.connect(
        host=settings.db_host,
        port=settings.db_port,
        user=settings.db_user,
        password=settings.db_password,
        database=settings.db_name,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
        connect_timeout=10,
        read_timeout=30,
        write_timeout=30,
    )


@contextmanager
def conn():
    db = _connect()
    session = DBSession(db)
    try:
        yield session
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def wait_for_db(attempts: int = 30, delay_seconds: int = 2):
    last_error = None
    for _ in range(attempts):
        try:
            db = _connect()
            db.close()
            return
        except Exception as exc:
            last_error = exc
            time.sleep(delay_seconds)
    raise RuntimeError(f"MySQL is not ready after {attempts} attempts: {last_error}")


def init_db():
    wait_for_db()
    with conn() as db:
        for statement in SCHEMA:
            db.execute(statement)

        # Forward-only migrations for existing installations.
        columns = {
            row["COLUMN_NAME"]
            for row in db.execute(
                """SELECT COLUMN_NAME
                   FROM INFORMATION_SCHEMA.COLUMNS
                   WHERE TABLE_SCHEMA=? AND TABLE_NAME='users'""",
                (settings.db_name,),
            ).fetchall()
        }
        if "computer_number" not in columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN computer_number VARCHAR(64) NULL AFTER last_name"
            )
        if "password_reset_method" not in columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN password_reset_method VARCHAR(32) NOT NULL DEFAULT 'automatic' AFTER generated_password_enc"
            )
        if "manual_password_generated_at" not in columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN manual_password_generated_at DATETIME NULL AFTER password_reset_method"
            )
        if "manual_password_confirmed_at" not in columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN manual_password_confirmed_at DATETIME NULL AFTER manual_password_generated_at"
            )


def reset_test_data():
    """Clear application data while preserving the MySQL schema."""
    with conn() as db:
        db.execute("SET FOREIGN_KEY_CHECKS=0")
        for table in ("events", "users", "settings", "runtime"):
            db.execute(f"TRUNCATE TABLE {table}")
        db.execute("SET FOREIGN_KEY_CHECKS=1")


def set_setting(key: str, value: str, is_secret: bool = False):
    with conn() as db:
        db.execute(
            """INSERT INTO settings(`key`,`value`,is_secret) VALUES(?,?,?)
               ON DUPLICATE KEY UPDATE
                 `value`=VALUES(`value`),
                 is_secret=VALUES(is_secret)""",
            (key, value, 1 if is_secret else 0),
        )


def get_setting(key: str) -> str | None:
    with conn() as db:
        row = db.execute("SELECT `value` FROM settings WHERE `key`=?", (key,)).fetchone()
        return row["value"] if row else None


def set_runtime(key: str, value: str):
    with conn() as db:
        db.execute(
            """INSERT INTO runtime(`key`,`value`) VALUES(?,?)
               ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)""",
            (key, value),
        )


def get_runtime(key: str, default: str | None = None) -> str | None:
    with conn() as db:
        row = db.execute("SELECT `value` FROM runtime WHERE `key`=?", (key,)).fetchone()
        return row["value"] if row else default


def log_event(user_id: int | None, event_type: str, message: str):
    with conn() as db:
        db.execute(
            "INSERT INTO events(user_id,event_type,message) VALUES(?,?,?)",
            (user_id, event_type, message[:4000]),
        )
