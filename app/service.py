import json
from app.config import settings
from app.db import conn, get_setting, get_runtime, set_runtime, log_event
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
    client = _cloudiway_client()
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

    password = generate_password()
    rack = _rackspace_client()
    cloud = _cloudiway_client()

    try:
        await rack.get_mailbox(user["source_email"])
        await rack.reset_password(user["source_email"], password)
        encrypted = encrypt_secret(password)
        with conn() as db:
            db.execute(
                "UPDATE users SET generated_password_enc=?,rackspace_status='reset_ok',attempt_count=attempt_count+1,error_message=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (encrypted, user_id),
            )
        log_event(user_id, "rackspace_password_reset", "Rackspace mailbox password changed")

        object_id = await ensure_cloudiway_user(user)
        token = await cloud.get_self_service_token(object_id)
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
        cloud = _cloudiway_client()
        try:
            await cloud.start_migration(object_ids)
            with conn() as db:
                placeholders = ",".join("?" for _ in user_ids)
                db.execute(
                    f"UPDATE users SET migration_status='migrating',batch_number=?,updated_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders}) AND cloudiway_object_id IS NOT NULL AND migration_status!='failed'",
                    (batch_number, *user_ids),
                )
            log_event(None, "batch_started", f"Batch {batch_number} started with {len(object_ids)} users")
        except Exception as exc:
            with conn() as db:
                placeholders = ",".join("?" for _ in user_ids)
                db.execute(
                    f"UPDATE users SET migration_status='failed',error_message=?,updated_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders}) AND migration_status!='failed'",
                    (str(exc)[:3000], *user_ids),
                )
            log_event(None, "batch_start_failed", str(exc))
            failed.extend([x for x in user_ids if x not in failed])

    set_runtime("automation_running", "1")
    if failed and settings.pause_on_any_failure:
        set_runtime("automation_paused", "1")
        set_runtime("pause_reason", f"Batch {batch_number} has {len(set(failed))} failed user(s)")


async def launch_next_batch(force: bool = False) -> dict:
    paused = get_runtime("automation_paused", "0") == "1"
    if paused and not force:
        return {"started": False, "reason": get_runtime("pause_reason", "Automation is paused")}

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
    cloud = _cloudiway_client()
    with conn() as db:
        rows = db.execute(
            "SELECT id,cloudiway_object_id,migration_status FROM users WHERE cloudiway_object_id IS NOT NULL AND migration_status IN ('migrating','ready')"
        ).fetchall()

    updated = 0
    completed = 0
    failed = 0
    for row in rows:
        try:
            data = await cloud.progress(int(row["cloudiway_object_id"]), settings.status_poll_seconds)
            status, percent, detail = parse_progress(data)
            with conn() as db:
                db.execute(
                    "UPDATE users SET migration_status=?,progress_percent=?,progress_detail=?,cloudiway_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (status, percent, detail, status, row["id"]),
                )
            updated += 1
            completed += int(status == "completed")
            failed += int(status == "failed")
        except Exception as exc:
            log_event(row["id"], "status_refresh_error", str(exc))

    if failed and settings.pause_on_any_failure:
        set_runtime("automation_paused", "1")
        set_runtime("pause_reason", f"{failed} migration(s) failed")
    elif settings.auto_continue and rows and all_terminal_for_latest_batch():
        await launch_next_batch()

    return {"updated": updated, "completed": completed, "failed": failed}


def parse_progress(data) -> tuple[str, float | None, str]:
    detail = json.dumps(data, default=str)[:1500]
    status_values: list[str] = []
    failure_count = 0
    percent = None

    def walk(obj):
        nonlocal failure_count, percent
        if isinstance(obj, dict):
            for key, value in obj.items():
                lk = str(key).lower()
                if any(x in lk for x in ("status", "state", "result")) and isinstance(value, (str, int)):
                    status_values.append(str(value).lower())
                if any(x in lk for x in ("failed", "fatal", "errorcount", "errorscount")) and isinstance(value, (int, float)):
                    failure_count += int(value)
                if percent is None and lk in ("percent", "percentage", "progresspercent", "progresspercentage") and isinstance(value, (int, float)):
                    percent = float(value)
                    if percent <= 1:
                        percent *= 100
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    joined = " ".join(status_values)
    if failure_count > 0 or any(word in joined for word in ("failed", "fatal", "error", "faulted")):
        status = "failed"
    elif any(word in joined for word in ("completed", "complete", "success", "succeeded", "finished")):
        status = "completed"
    elif percent is not None and percent >= 100:
        status = "completed"
    else:
        status = "migrating"
    return status, percent, detail


def all_terminal_for_latest_batch() -> bool:
    with conn() as db:
        latest = db.execute("SELECT COALESCE(MAX(batch_number),0) n FROM users").fetchone()["n"]
        if not latest:
            return False
        row = db.execute(
            "SELECT COUNT(*) total, SUM(CASE WHEN migration_status IN ('completed','failed') THEN 1 ELSE 0 END) terminal FROM users WHERE batch_number=?",
            (latest,),
        ).fetchone()
        return bool(row["total"] and row["terminal"] == row["total"])


async def rotate_user_password(user_id: int) -> str:
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise RuntimeError("User not found")
    user = dict(row)
    password = generate_password()
    rack = _rackspace_client()
    await rack.reset_password(user["source_email"], password)
    with conn() as db:
        db.execute(
            "UPDATE users SET generated_password_enc=?,rackspace_status='reset_ok',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (encrypt_secret(password), user_id),
        )
    if user.get("cloudiway_object_id"):
        cloud = _cloudiway_client()
        token = await cloud.get_self_service_token(int(user["cloudiway_object_id"]))
        await cloud.register_source_credentials(token, user["source_email"], password)
        with conn() as db:
            db.execute(
                "UPDATE users SET cloudiway_status='credentials_set',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (user_id,),
            )
    log_event(user_id, "password_rotated", "Administrator generated and applied a new Rackspace password")
    return password
