import json
from datetime import datetime, timezone

from app.config import settings
from app.db import conn, get_setting, get_runtime, set_runtime, log_event, set_setting
from app.security import decrypt_secret, encrypt_secret, generate_password
from app.clients.rackspace import RackspaceClient
from app.clients.cloudiway import CloudiwayClient


def _rackspace_client() -> RackspaceClient:
    mode = get_setting("rackspace_auth_mode") or "api_key"
    customer = get_setting("rackspace_customer_id") or ""

    if mode == "username_password":
        username = get_setting("rackspace_username") or ""
        password = decrypt_secret(get_setting("rackspace_password"))
        if not username or not password:
            raise RuntimeError("Rackspace username/password settings are incomplete")
        return RackspaceClient(
            customer_id=customer,
            auth_mode="username_password",
            username=username,
            password=password,
        )

    user_key = get_setting("rackspace_user_key")
    secret = decrypt_secret(get_setting("rackspace_secret_key"))
    if not all([user_key, secret, customer]):
        raise RuntimeError("Rackspace Email API settings are incomplete")
    return RackspaceClient(
        user_key=user_key,
        secret_key=secret,
        customer_id=customer,
        auth_mode="api_key",
    )


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
            # An invalid/expired refresh token cannot recover by retrying every
            # poll cycle. Clear the unusable session once and require a fresh
            # Cloudiway login instead of flooding the event log.
            set_setting("cloudiway_token", "", True)
            set_setting("cloudiway_refresh_token", "", True)
            set_setting("cloudiway_token_expiration", "")
            set_runtime("automation_paused", "1")
            set_runtime(
                "pause_reason",
                "Cloudiway session expired or refresh token is invalid. Reconnect Cloudiway in Connections.",
            )
            log_event(
                None,
                "cloudiway_reauthentication_required",
                "Cloudiway token refresh failed; stored session cleared. Reconnect Cloudiway in Connections. "
                + str(exc)[:1000],
            )
            raise RuntimeError(
                "Cloudiway session expired or refresh token is invalid. "
                "Go to Connections and sign in to Cloudiway again."
            ) from exc
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
            log_event(user["id"], "cloudiway_user_found", "Existing Cloudiway mail user found")
            return object_id
    except Exception as exc:
        # Do not hide authorization/project failures. A 403 here usually means
        # the authenticated account cannot access this project/mail endpoint.
        message = str(exc)
        log_event(user["id"], "cloudiway_verify_user_failed", message)
        if "(401)" in message or "(403)" in message:
            raise RuntimeError(
                "Cloudiway denied access while checking this mail user. "
                "Reconnect Cloudiway and verify the selected project and account permissions. "
                + message
            ) from exc
        # Non-auth lookup failures may simply mean the user does not exist;
        # continue to the create call in that case.

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


def _cloudiway_preflight():
    _cloudiway_client()
    if not get_setting("cloudiway_source_pool_id") or not get_setting("cloudiway_target_pool_id"):
        raise RuntimeError("Cloudiway source and target connector pools are not configured")


def _automatic_preflight():
    _rackspace_client()
    _cloudiway_preflight()


async def launch_next_confirmed_manual_batch() -> dict:
    """Launch the next group of manually-confirmed Rackspace users without Rackspace API."""
    try:
        _cloudiway_preflight()
    except Exception as exc:
        return {"started": False, "reason": str(exc), "mode": "manual"}

    with conn() as db:
        active = db.execute(
            "SELECT COUNT(*) c FROM users WHERE migration_status IN ('preparing','ready','migrating')"
        ).fetchone()["c"]
        if active:
            return {"started": False, "reason": "A batch is already active", "mode": "manual"}

        max_batch = db.execute("SELECT COALESCE(MAX(batch_number),0) n FROM users").fetchone()["n"]
        size = settings.pilot_size if max_batch == 0 else settings.batch_size
        rows = db.execute(
            """SELECT id FROM users
               WHERE migration_status='waiting'
                 AND password_reset_method='manual_bulk'
                 AND rackspace_status='manual_confirmed'
               ORDER BY id LIMIT ?""",
            (size,),
        ).fetchall()

    if not rows:
        return {"started": False, "reason": "No manually confirmed users are waiting", "mode": "manual"}

    ids = [int(r["id"]) for r in rows]
    result = await start_manual_migrations(ids)
    result["mode"] = "manual"
    return result


async def launch_next_batch(force: bool = False) -> dict:
    paused = get_runtime("automation_paused", "0") == "1"
    if paused and not force:
        return {"started": False, "reason": get_runtime("pause_reason", "Automation is paused")}

    try:
        _automatic_preflight()
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
            """SELECT id FROM users
               WHERE migration_status='waiting'
                 AND COALESCE(password_reset_method,'automatic')='automatic'
               ORDER BY id LIMIT ?""",
            (size,),
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
            error_message = None
            cloud_status = status

            logs_data = None
            if status in ("attention", "failed"):
                try:
                    logs_data = await cloud.logs(int(row["cloudiway_object_id"]))
                except Exception as log_exc:
                    log_event(row["id"], "cloudiway_logs_fetch_failed", str(log_exc))

                status_override, issue_code, friendly = classify_cloudiway_issue(data, logs_data)
                if status_override:
                    status = status_override
                    cloud_status = issue_code or status_override
                    error_message = friendly
                    log_event(
                        row["id"],
                        issue_code or "cloudiway_known_error",
                        friendly + " Raw Cloudiway logs: " + json.dumps(logs_data, default=str)[:2200],
                    )
                elif status == "attention":
                    error_message = (
                        "Cloudiway returned a status/value that requires review. "
                        "Open Logs & Issues for the raw Cloudiway response."
                    )
                    log_event(
                        row["id"],
                        "cloudiway_status_attention",
                        "Cloudiway progress requires review. Raw progress: "
                        + detail
                        + " Raw logs: "
                        + json.dumps(logs_data, default=str)[:2200],
                    )
                else:
                    error_message = "Cloudiway reported the migration as failed. Review Logs & Issues."
                    log_event(
                        row["id"],
                        "cloudiway_status_failed",
                        "Cloudiway progress reported failure. Raw progress: "
                        + detail
                        + " Raw logs: "
                        + json.dumps(logs_data, default=str)[:2200],
                    )

            with conn() as db:
                db.execute(
                    """UPDATE users
                       SET migration_status=?,progress_percent=?,progress_detail=?,
                           cloudiway_status=?,error_message=?,updated_at=CURRENT_TIMESTAMP
                       WHERE id=?""",
                    (status, percent, detail, cloud_status, error_message, row["id"]),
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
        manual_result = await launch_next_confirmed_manual_batch()
        if not manual_result.get("started"):
            await launch_next_batch()

    return {
        "updated": updated,
        "completed": completed,
        "failed": failed,
        "attention": attention,
        "timed_out": timed_out,
    }


def classify_cloudiway_issue(progress_data, logs_data=None) -> tuple[str | None, str | None, str | None]:
    """Map known Cloudiway log messages to actionable migration errors."""
    combined = json.dumps(
        {"progress": progress_data, "logs": logs_data},
        default=str,
    ).lower()

    if "smtp address has no mailbox associated with it" in combined:
        return (
            "failed",
            "target_mailbox_missing",
            "Target mailbox is not provisioned in Microsoft 365. "
            "Cloudiway authenticated to the target, but Exchange Online could not find "
            "a mailbox for the target SMTP address. Verify the Exchange Online licence, "
            "mailbox provisioning, and primary SMTP address, then retry.",
        )

    if "unable to connect to mailbox in the target" in combined:
        return (
            "failed",
            "target_mailbox_connection_failed",
            "Cloudiway could not open the target Microsoft 365 mailbox. "
            "Verify that the mailbox exists in Exchange Online and that the target connector "
            "has access to it.",
        )

    if "unable to connect to mailbox in the source" in combined:
        return (
            "failed",
            "source_mailbox_connection_failed",
            "Cloudiway could not open the source Rackspace mailbox. "
            "Verify the source mailbox exists and that the generated password was applied.",
        )

    if "invalid credential" in combined or "authentication failed" in combined:
        return (
            "failed",
            "mailbox_authentication_failed",
            "Mailbox authentication failed. Verify the source password/credentials and connector access.",
        )

    return None, None, None


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


async def prepare_manual_user(user_id: int) -> int:
    """Register a manually-applied Rackspace password with Cloudiway."""
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise RuntimeError(f"User {user_id} not found")
    user = dict(row)

    if user.get("password_reset_method") != "manual_bulk":
        raise RuntimeError("User is not assigned to the manual Rackspace reset workflow")
    if user.get("rackspace_status") != "manual_confirmed":
        raise RuntimeError("Rackspace password has not been confirmed as applied")
    if not user.get("generated_password_enc"):
        raise RuntimeError("No generated Rackspace password is stored for this user")

    password = decrypt_secret(user["generated_password_enc"])
    cloud = await _cloudiway_client_ready()
    object_id = await ensure_cloudiway_user(user)
    token = await cloud.get_self_service_token(object_id)
    await cloud.register_source_credentials(token, user["source_email"], password)

    with conn() as db:
        db.execute(
            """UPDATE users
               SET cloudiway_status='credentials_set',
                   migration_status='ready',
                   error_message=NULL,
                   updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (user_id,),
        )
    log_event(
        user_id,
        "manual_cloudiway_credentials",
        "Manually-applied Rackspace password registered with Cloudiway",
    )
    return object_id


async def start_manual_migrations(user_ids: list[int]) -> dict:
    """Start Cloudiway migrations without using the Rackspace administration API."""
    if not user_ids:
        return {"started": False, "reason": "No users selected"}

    _cloudiway_client()
    if not get_setting("cloudiway_source_pool_id") or not get_setting("cloudiway_target_pool_id"):
        raise RuntimeError("Cloudiway source and target connector pools are not configured")

    object_ids: list[int] = []
    started_user_ids: list[int] = []
    failed: list[dict] = []

    with conn() as db:
        max_batch = db.execute(
            "SELECT COALESCE(MAX(batch_number),0) n FROM users"
        ).fetchone()["n"]
    batch_no = int(max_batch or 0) + 1

    for uid in user_ids:
        try:
            oid = await prepare_manual_user(uid)
            object_ids.append(oid)
            started_user_ids.append(uid)
        except Exception as exc:
            failed.append({"user_id": uid, "error": str(exc)})
            with conn() as db:
                db.execute(
                    """UPDATE users SET migration_status='failed',error_message=?,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (str(exc)[:3000], uid),
                )
            log_event(uid, "manual_migration_prepare_failed", str(exc))

    if object_ids:
        try:
            cloud = await _cloudiway_client_ready()
            await cloud.start_migration(object_ids)
            with conn() as db:
                placeholders = ",".join("?" for _ in started_user_ids)
                db.execute(
                    f"""UPDATE users
                        SET migration_status='migrating',
                            batch_number=?,
                            batch_started_at=CURRENT_TIMESTAMP,
                            updated_at=CURRENT_TIMESTAMP
                        WHERE id IN ({placeholders})""",
                    (batch_no, *started_user_ids),
                )
            log_event(
                None,
                "manual_batch_started",
                f"Manual Rackspace batch {batch_no} started with {len(started_user_ids)} users",
            )
            set_runtime("automation_running", "1")
        except Exception as exc:
            with conn() as db:
                placeholders = ",".join("?" for _ in started_user_ids)
                db.execute(
                    f"""UPDATE users
                        SET migration_status='failed',error_message=?,
                            updated_at=CURRENT_TIMESTAMP
                        WHERE id IN ({placeholders})""",
                    (str(exc)[:3000], *started_user_ids),
                )
            failed.extend(
                {"user_id": uid, "error": str(exc)} for uid in started_user_ids
            )
            object_ids = []
            started_user_ids = []
            log_event(None, "manual_batch_start_failed", str(exc))

    if failed and settings.pause_on_any_failure:
        set_runtime("automation_paused", "1")
        set_runtime(
            "pause_reason",
            f"Manual migration has {len(failed)} failed user(s)",
        )

    return {
        "started": bool(started_user_ids),
        "batch": batch_no if started_user_ids else None,
        "users_started": len(started_user_ids),
        "failed": failed,
    }


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
