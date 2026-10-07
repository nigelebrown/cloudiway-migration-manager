import json
from datetime import datetime, timezone

from app.config import settings
from app.db import conn, get_setting, get_runtime, set_runtime, log_event, set_setting
from app.security import decrypt_secret, encrypt_secret, generate_password
from app.clients.rackspace import RackspaceClient
from app.clients.cloudiway import CloudiwayClient


def _rackspace_client() -> RackspaceClient:
    user_key = get_setting("rackspace_user_key")
    secret = decrypt_secret(get_setting("rackspace_secret_key"))
    customer = get_setting("rackspace_customer_id")
    if not all([user_key, secret, customer]):
        raise RuntimeError("Rackspace API settings are incomplete")
    return RackspaceClient(user_key, secret, customer)


def _cloudiway_client() -> CloudiwayClient:
    token = decrypt_secret(get_setting("cloudiway_token"))
    project_header = get_setting("cloudiway_project_header") or settings.cloudiway_project_header
    if not token:
        raise RuntimeError("Cloudiway is not connected")
    return CloudiwayClient(token=token, project_header=project_header)


async def _cloudiway_client_ready() -> CloudiwayClient:
    client = _cloudiway_client()
    expiration = get_setting("cloudiway_token_expiration")
    refresh = decrypt_secret(get_setting("cloudiway_refresh_token"))
    if expiration and refresh:
        try:
            exp = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if (exp - datetime.now(timezone.utc)).total_seconds() < 120:
                data = await client.refresh_token(client.token, refresh)
                if data.get("token"):
                    set_setting("cloudiway_token", encrypt_secret(data["token"]), True)
                    client.token = data["token"]
                if data.get("refreshToken"):
                    set_setting("cloudiway_refresh_token", encrypt_secret(data["refreshToken"]), True)
                if data.get("expiration"):
                    set_setting("cloudiway_token_expiration", data["expiration"])
        except Exception as exc:
            log_event(None, "cloudiway_token_refresh_failed", str(exc))
    return client


def _extract_object_id(data) -> int | None:
    candidates = []
    if isinstance(data, dict):
        candidates.extend([data.get("id"), data.get("objectId")])
        rd = data.get("responseData")
        if isinstance(rd, dict):
            candidates.extend([rd.get("id"), rd.get("objectId")])
        elif isinstance(rd, list) and rd and isinstance(rd[0], dict):
            candidates.extend([rd[0].get("id"), rd[0].get("objectId")])
    for value in candidates:
        if value not in (None, ""):
            return int(value)
    return None


async def ensure_cloudiway_user(user: dict) -> int:
    client = await _cloudiway_client_ready()
    source_pool = get_setting("cloudiway_source_pool_id")
    target_pool = get_setting("cloudiway_target_pool_id")
    if not source_pool or not target_pool:
        raise RuntimeError("Select the Cloudiway source and target connector pools first")

    if user.get("cloudiway_object_id"):
        return int(user["cloudiway_object_id"])

    try:
        found = await client.verify_mail_user(user["source_email"])
        object_id = _extract_object_id(found)
        if object_id:
            with conn() as db:
                db.execute(
                    "UPDATE users SET cloudiway_object_id=?,cloudiway_status='existing',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (object_id, user["id"]),
                )
            return object_id
    except Exception:
        pass

    payload = {
        "id": 0,
        "firstName": user.get("first_name") or "",
        "lastName": user.get("last_name") or "",
        "sourcePoolId": int(source_pool),
        "targetPoolId": int(target_pool),
        "sourceEmail": user["source_email"],
        "targetEmail": user["target_email"],
        "sourceRecipientType": 0,
        "targetRecipientType": 0,
        "sku": 0,
        "isLocked": False,
        "mailForwarderSetting": 0,
    }
    created = await client.create_mail_user(payload)
    object_id = _extract_object_id(created)
    if not object_id:
        verify = await client.verify_mail_user(user["source_email"])
        object_id = _extract_object_id(verify)
    if not object_id:
        raise RuntimeError(f"Cloudiway user was created/submitted but no object ID was returned: {created}")
    with conn() as db:
        db.execute(
            "UPDATE users SET cloudiway_object_id=?,cloudiway_status='created',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (object_id, user["id"]),
        )
    return object_id


async def prepare_user(user_id: int) -> int:
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise RuntimeError(f"User {user_id} not found")
    user = dict(row)

    try:
        rack = _rackspace_client()
        cloud = await _cloudiway_client_ready()

        await rack.get_mailbox(user["source_email"])

        # Validate/create Cloudiway record and obtain a credential token before
        # changing the live Rackspace password.
        object_id = await ensure_cloudiway_user(user)
        token = await cloud.get_self_service_token(object_id)

        password = generate_password()
        await rack.reset_password(user["source_email"], password)

        encrypted = encrypt_secret(password)
        with conn() as db:
            db.execute(
                "UPDATE users SET generated_password_enc=?,rackspace_status='reset_ok',attempt_count=attempt_count+1,error_message=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (encrypted, user_id),
            )
        log_event(user_id, "rackspace_password_reset", "Rackspace mailbox password changed")

        await cloud.register_source_credentials(token, user["source_email"], password)
        with conn() as db:
            db.execute(
                "UPDATE users SET cloudiway_status='credentials_set',migration_status='ready',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (user_id,),
            )
        log_event(user_id, "cloudiway_credentials", "Source credentials registered in Cloudiway")
        return object_id
    except Exception as exc:
        with conn() as db:
            db.execute(
                "UPDATE users SET migration_status='failed',error_message=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (str(exc)[:3000], user_id),
            )
        log_event(user_id, "prepare_failed", str(exc))
        raise


async def run_batch(user_ids: list[int], batch_number: int):
    object_ids: list[int] = []
    failed: list[int] = []

    for uid in user_ids:
        try:
            oid = await prepare_user(uid)
            object_ids.append(oid)
        except Exception:
            failed.append(uid)

    if object_ids:
        try:
            cloud = await _cloudiway_client_ready()
            await cloud.start_migration(object_ids)
            with conn() as db:
                placeholders = ",".join("?" for _ in user_ids)
                db.execute(
                    f"UPDATE users SET migration_status='migrating',batch_number=?,batch_started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP "
                    f"WHERE id IN ({placeholders}) AND cloudiway_object_id IS NOT NULL AND migration_status!='failed'",
                    (batch_number, *user_ids),
                )
            log_event(None, "batch_started", f"Batch {batch_number} started with {len(object_ids)} users")
        except Exception as exc:
            with conn() as db:
                placeholders = ",".join("?" for _ in user_ids)
                db.execute(
                    f"UPDATE users SET migration_status='failed',error_message=?,updated_at=CURRENT_TIMESTAMP "
                    f"WHERE id IN ({placeholders}) AND migration_status!='failed'",
                    (str(exc)[:3000], *user_ids),
                )
            log_event(None, "batch_start_failed", str(exc))
            failed.extend([x for x in user_ids if x not in failed])

    set_runtime("automation_running", "1")
    if failed and settings.pause_on_any_failure:
        set_runtime("automation_paused", "1")
        set_runtime("pause_reason", f"Batch {batch_number} has {len(set(failed))} failed user(s)")


def _preflight():
    _rackspace_client()
    _cloudiway_client()
    if not get_setting("cloudiway_source_pool_id") or not get_setting("cloudiway_target_pool_id"):
        raise RuntimeError("Cloudiway source and target connector pools are not configured")


async def launch_next_batch(force: bool = False) -> dict:
    paused = get_runtime("automation_paused", "0") == "1"
    if paused and not force:
        return {"started": False, "reason": get_runtime("pause_reason", "Automation is paused")}

    try:
        _preflight()
    except Exception as exc:
        set_runtime("automation_paused", "1")
        set_runtime("pause_reason", str(exc))
        return {"started": False, "reason": str(exc)}

    with conn() as db:
        active = db.execute(
            "SELECT COUNT(*) c FROM users WHERE migration_status IN ('preparing','ready','migrating')"
        ).fetchone()["c"]
        if active:
            return {"started": False, "reason": "A batch is already active"}

        max_batch = db.execute("SELECT COALESCE(MAX(batch_number),0) n FROM users").fetchone()["n"]
        size = settings.pilot_size if max_batch == 0 else settings.batch_size
        rows = db.execute(
            "SELECT id FROM users WHERE migration_status='waiting' ORDER BY id LIMIT ?", (size,)
        ).fetchall()
        if not rows:
            return {"started": False, "reason": "No waiting users"}

        ids = [r["id"] for r in rows]
        batch_no = int(max_batch) + 1
        placeholders = ",".join("?" for _ in ids)
        db.execute(
            f"UPDATE users SET migration_status='preparing',batch_number=? WHERE id IN ({placeholders})",
            (batch_no, *ids),
        )

    await run_batch(ids, batch_no)
    return {"started": True, "batch": batch_no, "users": len(ids)}


async def refresh_status() -> dict:
    cloud = await _cloudiway_client_ready()
    with conn() as db:
        rows = db.execute(
            "SELECT id,cloudiway_object_id,migration_status FROM users "
            "WHERE cloudiway_object_id IS NOT NULL AND migration_status IN ('migrating','ready')"
        ).fetchall()

    updated = completed = failed = attention = timed_out = 0
    for row in rows:
        try:
            data = await cloud.progress(
                int(row["cloudiway_object_id"]),
                max(1, settings.progress_window_minutes),
            )
            status, percent, detail = parse_progress(data)
            with conn() as db:
                db.execute(
                    "UPDATE users SET migration_status=?,progress_percent=?,progress_detail=?,cloudiway_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (status, percent, detail, status, row["id"]),
                )
            updated += 1
            completed += int(status == "completed")
            failed += int(status == "failed")
            attention += int(status == "attention")
        except Exception as exc:
            log_event(row["id"], "status_refresh_error", str(exc))

    if settings.batch_timeout_minutes > 0:
        with conn() as db:
            stale = db.execute(
                """SELECT id FROM users
                   WHERE migration_status IN ('migrating','ready')
                     AND batch_started_at IS NOT NULL
                     AND TIMESTAMPDIFF(MINUTE, batch_started_at, UTC_TIMESTAMP()) >= ?""",
                (int(settings.batch_timeout_minutes),),
            ).fetchall()
            if stale:
                ids = [row["id"] for row in stale]
                placeholders = ",".join("?" for _ in ids)
                db.execute(
                    f"UPDATE users SET migration_status='timed_out',cloudiway_status='timed_out',"
                    f"error_message='Migration exceeded configured timeout; review Cloudiway before retrying.',"
                    f"updated_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders})",
                    ids,
                )
                timed_out = len(ids)

    if timed_out:
        log_event(None, "batch_timeout", f"{timed_out} migration(s) exceeded the configured timeout")

    if (failed or attention or timed_out) and settings.pause_on_any_failure:
        set_runtime("automation_paused", "1")
        if timed_out:
            reason = f"{timed_out} migration(s) exceeded the configured timeout"
        elif attention:
            reason = f"{attention} migration(s) returned a Cloudiway status requiring review"
        else:
            reason = f"{failed} migration(s) failed"
        set_runtime("pause_reason", reason)
    elif settings.auto_continue and rows and all_terminal_for_latest_batch():
        await launch_next_batch()

    return {
        "updated": updated,
        "completed": completed,
        "failed": failed,
        "attention": attention,
        "timed_out": timed_out,
    }


def parse_progress(data) -> tuple[str, float | None, str]:
    detail = json.dumps(data, default=str)[:1500]
    text_statuses: list[str] = []
    numeric_status_seen = False
    percent = None

    def walk(obj):
        nonlocal percent, numeric_status_seen
        if isinstance(obj, dict):
            for key, value in obj.items():
                lk = str(key).lower()
                if lk in ("status", "state", "jobstatus", "migrationstatus"):
                    if isinstance(value, str):
                        text_statuses.append(value.strip().lower())
                    elif isinstance(value, (int, float)):
                        numeric_status_seen = True
                if percent is None and lk in ("percent", "percentage", "progresspercent", "progresspercentage") and isinstance(value, (int, float)):
                    percent = float(value)
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    normalized = {s.replace("_", " ").replace("-", " ").strip() for s in text_statuses if s.strip()}

    active = {
        "running", "migrating", "in progress", "processing", "pending",
        "queued", "started", "starting", "active", "auditing", "ready",
    }
    failed = {"failed", "error", "errored", "faulted"}
    complete = {"completed", "complete", "success", "succeeded", "finished", "done"}
    needs_review = {
        "stopped", "cancelled", "canceled", "aborted", "terminated",
        "completed with warnings", "complete with warnings",
        "partially completed", "partial success",
    }

    if normalized & failed:
        status = "failed"
    elif normalized & needs_review:
        status = "attention"
    elif normalized & complete:
        status = "completed"
    elif normalized and normalized.issubset(active):
        status = "completed" if percent is not None and percent >= 100 else "migrating"
    elif normalized:
        status = "attention"
    elif percent is not None and percent >= 100:
        status = "completed"
    elif numeric_status_seen or percent is not None:
        status = "migrating"
    else:
        status = "attention"

    return status, percent, detail

def all_terminal_for_latest_batch() -> bool:
    with conn() as db:
        latest = db.execute("SELECT COALESCE(MAX(batch_number),0) n FROM users").fetchone()["n"]
        if not latest:
            return False
        row = db.execute(
            "SELECT COUNT(*) total, "
            "SUM(CASE WHEN migration_status IN ('completed','failed','attention','timed_out') THEN 1 ELSE 0 END) terminal "
            "FROM users WHERE batch_number=?",
            (latest,),
        ).fetchone()
        return bool(row["total"] and row["terminal"] == row["total"])


async def rotate_user_password(user_id: int) -> str:
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise RuntimeError("User not found")

    user = dict(row)
    rack = _rackspace_client()
    cloud = await _cloudiway_client_ready()

    if user.get("cloudiway_object_id"):
        token = await cloud.get_self_service_token(int(user["cloudiway_object_id"]))
    else:
        object_id = await ensure_cloudiway_user(user)
        token = await cloud.get_self_service_token(object_id)

    password = generate_password()
    await rack.reset_password(user["source_email"], password)

    with conn() as db:
        db.execute(
            "UPDATE users SET generated_password_enc=?,rackspace_status='reset_ok',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (encrypt_secret(password), user_id),
        )

    await cloud.register_source_credentials(token, user["source_email"], password)
    with conn() as db:
        db.execute(
            "UPDATE users SET cloudiway_status='credentials_set',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (user_id,),
        )

    log_event(user_id, "password_rotated", "Administrator generated and applied a new Rackspace password")
    return password
