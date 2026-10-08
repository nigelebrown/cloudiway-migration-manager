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
        middle_name VARCHAR(255) NULL,
        last_name VARCHAR(255) NULL,
        computer_number VARCHAR(64) NULL,
        provisioning_profile_id BIGINT NULL,
        provisioning_status VARCHAR(64) NOT NULL DEFAULT 'not_checked',
        ad_match_status VARCHAR(64) NOT NULL DEFAULT 'not_checked',
        ad_object_guid VARCHAR(64) NULL,
        ad_distinguished_name VARCHAR(1024) NULL,
        ad_candidate_json LONGTEXT NULL,
        ad_conflict_reason LONGTEXT NULL,
        ad_created_by_app TINYINT(1) NOT NULL DEFAULT 0,
        ad_enabled_status VARCHAR(32) NULL,
        ad_group_status VARCHAR(64) NULL,
        ad_manual_override TINYINT(1) NOT NULL DEFAULT 0,
        ad_resolution_note LONGTEXT NULL,
        ad_resolved_at DATETIME NULL,
        entra_status VARCHAR(64) NOT NULL DEFAULT 'not_checked',
        entra_object_id VARCHAR(128) NULL,
        license_status VARCHAR(64) NOT NULL DEFAULT 'not_checked',
        mailbox_status VARCHAR(64) NOT NULL DEFAULT 'not_checked',
        provisioning_error LONGTEXT NULL,
        provisioning_updated_at DATETIME NULL,
        generated_password_enc LONGTEXT NULL,
        source_credential_username VARCHAR(320) NULL,
        source_credential_password_enc LONGTEXT NULL,
        source_credential_origin VARCHAR(32) NULL,
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
    CREATE TABLE IF NOT EXISTS environment_profiles (
        id BIGINT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(128) NOT NULL UNIQUE,
        environment_type VARCHAR(32) NOT NULL DEFAULT 'TEST',
        is_active TINYINT(1) NOT NULL DEFAULT 0,
        writes_enabled TINYINT(1) NOT NULL DEFAULT 0,
        emergency_stop TINYINT(1) NOT NULL DEFAULT 0,
        production_max_batch INT NOT NULL DEFAULT 100,

        ad_host VARCHAR(255) NULL,
        ad_port INT NOT NULL DEFAULT 636,
        ad_use_ssl TINYINT(1) NOT NULL DEFAULT 1,
        ad_tls_validate TINYINT(1) NOT NULL DEFAULT 1,
        ad_ca_cert_path VARCHAR(1024) NULL,
        ad_base_dn VARCHAR(1024) NULL,
        ad_bind_username VARCHAR(512) NULL,
        ad_bind_password_enc LONGTEXT NULL,
        ad_target_ou VARCHAR(1024) NULL,
        ad_license_group_dn VARCHAR(1024) NULL,
        ad_computer_number_attribute VARCHAR(128) NULL,
        ad_upn_suffix VARCHAR(255) NULL,
        ad_default_password_enc LONGTEXT NULL,
        ad_force_password_change TINYINT(1) NOT NULL DEFAULT 1,
        ad_allow_user_creation TINYINT(1) NOT NULL DEFAULT 0,
        ad_allow_group_changes TINYINT(1) NOT NULL DEFAULT 0,

        graph_tenant_id VARCHAR(128) NULL,
        graph_client_id VARCHAR(128) NULL,
        graph_client_secret_enc LONGTEXT NULL,
        graph_required_sku VARCHAR(128) NULL,

        sync_agent_url VARCHAR(1024) NULL,
        sync_agent_token_enc LONGTEXT NULL,

        sql_host VARCHAR(255) NULL,
        sql_port INT NOT NULL DEFAULT 1433,
        sql_database VARCHAR(255) NULL,
        sql_username VARCHAR(255) NULL,
        sql_password_enc LONGTEXT NULL,
        sql_source_view VARCHAR(512) NULL,

        vpn_profile_name VARCHAR(255) NULL,
        network_notes LONGTEXT NULL,

        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_environment_profiles_active (is_active),
        INDEX idx_environment_profiles_type (environment_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS upload_batches (
        id BIGINT PRIMARY KEY AUTO_INCREMENT,
        batch_name VARCHAR(255) NOT NULL UNIQUE,
        original_filename VARCHAR(512) NULL,
        workflow_mode VARCHAR(32) NOT NULL DEFAULT 'manual_bulk',
        workflow_status VARCHAR(64) NOT NULL DEFAULT 'uploaded',
        provisioning_profile_id BIGINT NULL,
        auto_start TINYINT(1) NOT NULL DEFAULT 0,
        cloudiway_batch_id BIGINT NULL,
        cloudiway_batch_name VARCHAR(255) NULL,
        total_rows INT NOT NULL DEFAULT 0,
        imported_rows INT NOT NULL DEFAULT 0,
        skipped_rows INT NOT NULL DEFAULT 0,
        protected_rows INT NOT NULL DEFAULT 0,
        last_error LONGTEXT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_upload_batches_status (workflow_status),
        INDEX idx_upload_batches_cloudiway (cloudiway_batch_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS upload_batch_members (
        upload_batch_id BIGINT NOT NULL,
        user_id BIGINT NOT NULL,
        row_order INT NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (upload_batch_id, user_id),
        INDEX idx_upload_batch_members_user (user_id),
        CONSTRAINT fk_upload_batch_members_batch
            FOREIGN KEY (upload_batch_id) REFERENCES upload_batches(id)
            ON DELETE CASCADE,
        CONSTRAINT fk_upload_batch_members_user
            FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS migration_batches (
        id BIGINT PRIMARY KEY AUTO_INCREMENT,
        upload_batch_id BIGINT NOT NULL,
        sequence_number INT NOT NULL,
        batch_name VARCHAR(255) NOT NULL UNIQUE,
        workflow_status VARCHAR(64) NOT NULL DEFAULT 'selected',
        provisioning_profile_id BIGINT NULL,
        sync_requested_at DATETIME NULL,
        m365_ready_at DATETIME NULL,
        auto_start TINYINT(1) NOT NULL DEFAULT 0,
        cloudiway_batch_id BIGINT NULL,
        cloudiway_batch_name VARCHAR(255) NULL,
        selected_count INT NOT NULL DEFAULT 0,
        confirmed_count INT NOT NULL DEFAULT 0,
        last_error LONGTEXT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_migration_batch_sequence (upload_batch_id, sequence_number),
        INDEX idx_migration_batches_upload (upload_batch_id),
        INDEX idx_migration_batches_status (workflow_status),
        INDEX idx_migration_batches_cloudiway (cloudiway_batch_id),
        CONSTRAINT fk_migration_batches_upload
            FOREIGN KEY (upload_batch_id) REFERENCES upload_batches(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS migration_batch_members (
        migration_batch_id BIGINT NOT NULL,
        user_id BIGINT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (migration_batch_id, user_id),
        INDEX idx_migration_batch_members_user (user_id),
        CONSTRAINT fk_migration_batch_members_batch
            FOREIGN KEY (migration_batch_id) REFERENCES migration_batches(id)
            ON DELETE CASCADE,
        CONSTRAINT fk_migration_batch_members_user
            FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE
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
        user_additions = [
            ("source_credential_username", "VARCHAR(320) NULL AFTER generated_password_enc"),
            ("source_credential_password_enc", "LONGTEXT NULL AFTER source_credential_username"),
            ("source_credential_origin", "VARCHAR(32) NULL AFTER source_credential_password_enc"),
            ("middle_name", "VARCHAR(255) NULL AFTER first_name"),
            ("provisioning_profile_id", "BIGINT NULL AFTER computer_number"),
            ("provisioning_status", "VARCHAR(64) NOT NULL DEFAULT 'not_checked' AFTER provisioning_profile_id"),
            ("ad_match_status", "VARCHAR(64) NOT NULL DEFAULT 'not_checked' AFTER provisioning_status"),
            ("ad_object_guid", "VARCHAR(64) NULL AFTER ad_match_status"),
            ("ad_distinguished_name", "VARCHAR(1024) NULL AFTER ad_object_guid"),
            ("ad_candidate_json", "LONGTEXT NULL AFTER ad_distinguished_name"),
            ("ad_conflict_reason", "LONGTEXT NULL AFTER ad_candidate_json"),
            ("ad_created_by_app", "TINYINT(1) NOT NULL DEFAULT 0 AFTER ad_conflict_reason"),
            ("ad_enabled_status", "VARCHAR(32) NULL AFTER ad_created_by_app"),
            ("ad_group_status", "VARCHAR(64) NULL AFTER ad_enabled_status"),
            ("ad_manual_override", "TINYINT(1) NOT NULL DEFAULT 0 AFTER ad_group_status"),
            ("ad_resolution_note", "LONGTEXT NULL AFTER ad_manual_override"),
            ("ad_resolved_at", "DATETIME NULL AFTER ad_resolution_note"),
            ("entra_status", "VARCHAR(64) NOT NULL DEFAULT 'not_checked' AFTER ad_resolved_at"),
            ("entra_object_id", "VARCHAR(128) NULL AFTER entra_status"),
            ("license_status", "VARCHAR(64) NOT NULL DEFAULT 'not_checked' AFTER entra_object_id"),
            ("mailbox_status", "VARCHAR(64) NOT NULL DEFAULT 'not_checked' AFTER license_status"),
            ("provisioning_error", "LONGTEXT NULL AFTER mailbox_status"),
            ("provisioning_updated_at", "DATETIME NULL AFTER provisioning_error"),
        ]
        for column_name, definition in user_additions:
            if column_name not in columns:
                db.execute(f"ALTER TABLE users ADD COLUMN {column_name} {definition}")
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

        upload_member_columns = {
            row["COLUMN_NAME"]
            for row in db.execute(
                """SELECT COLUMN_NAME
                   FROM INFORMATION_SCHEMA.COLUMNS
                   WHERE TABLE_SCHEMA=? AND TABLE_NAME='upload_batch_members'""",
                (settings.db_name,),
            ).fetchall()
        }
        if "row_order" not in upload_member_columns:
            db.execute(
                "ALTER TABLE upload_batch_members ADD COLUMN row_order INT NOT NULL DEFAULT 0 AFTER user_id"
            )

        upload_batch_columns = {
            row["COLUMN_NAME"]
            for row in db.execute(
                """SELECT COLUMN_NAME
                   FROM INFORMATION_SCHEMA.COLUMNS
                   WHERE TABLE_SCHEMA=? AND TABLE_NAME='upload_batches'""",
                (settings.db_name,),
            ).fetchall()
        }
        if "provisioning_profile_id" not in upload_batch_columns:
            db.execute(
                "ALTER TABLE upload_batches ADD COLUMN provisioning_profile_id BIGINT NULL AFTER workflow_status"
            )

        migration_batch_columns = {
            row["COLUMN_NAME"]
            for row in db.execute(
                """SELECT COLUMN_NAME
                   FROM INFORMATION_SCHEMA.COLUMNS
                   WHERE TABLE_SCHEMA=? AND TABLE_NAME='migration_batches'""",
                (settings.db_name,),
            ).fetchall()
        }
        for column_name, definition in [
            ("provisioning_profile_id", "BIGINT NULL AFTER workflow_status"),
            ("sync_requested_at", "DATETIME NULL AFTER provisioning_profile_id"),
            ("m365_ready_at", "DATETIME NULL AFTER sync_requested_at"),
        ]:
            if column_name not in migration_batch_columns:
                db.execute(f"ALTER TABLE migration_batches ADD COLUMN {column_name} {definition}")

        profile_columns = {
            row["COLUMN_NAME"]
            for row in db.execute(
                """SELECT COLUMN_NAME
                   FROM INFORMATION_SCHEMA.COLUMNS
                   WHERE TABLE_SCHEMA=? AND TABLE_NAME='environment_profiles'""",
                (settings.db_name,),
            ).fetchall()
        }
        if "ad_tls_validate" not in profile_columns:
            db.execute(
                "ALTER TABLE environment_profiles ADD COLUMN ad_tls_validate TINYINT(1) NOT NULL DEFAULT 1 AFTER ad_use_ssl"
            )
        if "ad_ca_cert_path" not in profile_columns:
            db.execute(
                "ALTER TABLE environment_profiles ADD COLUMN ad_ca_cert_path VARCHAR(1024) NULL AFTER ad_tls_validate"
            )

        migration_member_indexes = {
            row["INDEX_NAME"]
            for row in db.execute(
                """SELECT DISTINCT INDEX_NAME
                   FROM INFORMATION_SCHEMA.STATISTICS
                   WHERE TABLE_SCHEMA=? AND TABLE_NAME='migration_batch_members'""",
                (settings.db_name,),
            ).fetchall()
        }
        if "uq_user_one_migration_batch" in migration_member_indexes:
            db.execute(
                "ALTER TABLE migration_batch_members DROP INDEX uq_user_one_migration_batch"
            )


def reset_test_data():
    """Clear application data while preserving the MySQL schema."""
    with conn() as db:
        db.execute("SET FOREIGN_KEY_CHECKS=0")
        for table in ("events", "migration_batch_members", "migration_batches", "upload_batch_members", "upload_batches", "users", "environment_profiles", "settings", "runtime"):
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
