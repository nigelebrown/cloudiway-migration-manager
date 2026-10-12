import json
from datetime import datetime, timezone, timedelta

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


def _save_cloudiway_session(data: dict) -> None:
    if data.get("token"):
        set_setting("cloudiway_token", encrypt_secret(data["token"]), True)
    if data.get("refreshToken"):
        set_setting("cloudiway_refresh_token", encrypt_secret(data["refreshToken"]), True)
    if data.get("expiration"):
        set_setting("cloudiway_token_expiration", data["expiration"])


async def _cloudiway_reauthenticate() -> CloudiwayClient:
    if get_setting("cloudiway_keep_connected") != "1":
        raise RuntimeError("Background Cloudiway reauthentication is not enabled")

    username = get_setting("cloudiway_username") or ""
    password = decrypt_secret(get_setting("cloudiway_password"))
    if not username or not password:
        raise RuntimeError(
            "Cloudiway background reauthentication is enabled but stored credentials are incomplete"
        )

    login_project = (
        get_setting("cloudiway_project_name")
        or settings.cloudiway_project_header
        or "JCF"
    )
    login_client = CloudiwayClient(project_header=login_project)
    data = await login_client.login(username, password)
    if not data.get("token"):
        raise RuntimeError("Cloudiway reauthentication succeeded but returned no access token")

    _save_cloudiway_session(data)
    project_id = (
        get_setting("cloudiway_project_id")
        or get_setting("cloudiway_project_header")
        or login_project
    )
    log_event(
        None,
        "cloudiway_reauthenticated",
        "Cloudiway session was renewed automatically using encrypted stored credentials.",
    )
    return CloudiwayClient(token=data["token"], project_header=project_id)


async def _cloudiway_client_ready() -> CloudiwayClient:
    # If the access token is missing but the administrator chose to keep the
    # Cloudiway connection alive, transparently obtain a fresh session from the
    # encrypted stored credentials. This lets workflows continue after token
    # cleanup/expiry without forcing the operator back to Connections first.
    try:
        client = _cloudiway_client()
    except RuntimeError as exc:
        if "not connected" not in str(exc).lower():
            raise
        try:
            client = await _cloudiway_reauthenticate()
        except Exception as relogin_exc:
            raise RuntimeError(
                "Cloudiway is not connected and automatic reauthentication could not be completed. "
                "Go to Connections, sign in to Cloudiway, and enable Keep Cloudiway Connected."
            ) from relogin_exc

    expiration = get_setting("cloudiway_token_expiration")
    refresh = decrypt_secret(get_setting("cloudiway_refresh_token"))

    should_refresh = False
    if expiration:
        try:
            exp = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            # Refresh early enough that a long API operation does not start
            # with a token that is about to expire.
            should_refresh = (exp - datetime.now(timezone.utc)).total_seconds() < 300
        except Exception:
            should_refresh = True

    if should_refresh and refresh:
        try:
            data = await client.refresh_token(client.token, refresh)
            _save_cloudiway_session(data)
            if data.get("token"):
                client.token = data["token"]
            log_event(None, "cloudiway_token_refreshed", "Cloudiway access token refreshed automatically.")
        except Exception as refresh_exc:
            # Some Cloudiway sessions have returned an unusable refresh token.
            # If the admin opted into background connectivity, transparently
            # perform a fresh login using the encrypted stored credentials.
            try:
                client = await _cloudiway_reauthenticate()
            except Exception as relogin_exc:
                set_setting("cloudiway_token", "", True)
                set_setting("cloudiway_refresh_token", "", True)
                set_setting("cloudiway_token_expiration", "")
                set_runtime("automation_paused", "1")
                set_runtime(
                    "pause_reason",
                    "Cloudiway authentication expired and automatic reauthentication failed. Reconnect Cloudiway in Connections.",
                )
                log_event(
                    None,
                    "cloudiway_reauthentication_required",
                    "Refresh failed: "
                    + str(refresh_exc)[:700]
                    + " | automatic login failed: "
                    + str(relogin_exc)[:700],
                )
                raise RuntimeError(
                    "Cloudiway authentication expired and automatic reauthentication failed. "
                    "Go to Connections and sign in again."
                ) from relogin_exc

    elif should_refresh and not refresh:
        try:
            client = await _cloudiway_reauthenticate()
        except Exception as exc:
            set_runtime("automation_paused", "1")
            set_runtime(
                "pause_reason",
                "Cloudiway access token is expiring and no usable refresh/relogin method is available.",
            )
            raise RuntimeError(
                "Cloudiway access token is expiring. Enable Keep Cloudiway Connected and sign in again."
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


def _extract_cloudiway_batch_id(data, expected_name: str | None = None) -> int | None:
    """Extract a Cloudiway Mail Batch ID from create/list responses."""
    if isinstance(data, (int, float)) and int(data) > 0:
        return int(data)
    if isinstance(data, str) and data.strip().isdigit():
        return int(data.strip())

    wanted = (expected_name or "").strip().lower()

    def walk(value):
        if isinstance(value, list):
            for item in value:
                found = walk(item)
                if found:
                    return found
            return None
        if not isinstance(value, dict):
            return None

        name = str(value.get("name") or "").strip()
        bid = value.get("id")
        if bid not in (None, ""):
            if not wanted or (name and name.lower() == wanted):
                try:
                    return int(bid)
                except Exception:
                    pass

        for key in ("responseData", "data", "items", "batches", "results"):
            if key in value:
                found = walk(value[key])
                if found:
                    return found

        if not wanted:
            for child in value.values():
                if isinstance(child, (dict, list)):
                    found = walk(child)
                    if found:
                        return found
        return None

    return walk(data)


async def ensure_migration_cloudiway_batch(migration_batch_id: int) -> int:
    """Ensure one incremental migration batch has its own Cloudiway Mail Batch."""
    with conn() as db:
        batch = db.execute(
            """SELECT mb.*,ub.batch_name AS upload_name,ub.workflow_mode
               FROM migration_batches mb
               JOIN upload_batches ub ON ub.id=mb.upload_batch_id
               WHERE mb.id=?""",
            (migration_batch_id,),
        ).fetchone()
    if not batch:
        raise RuntimeError(f"Migration batch {migration_batch_id} was not found")
    if batch.get("cloudiway_batch_id"):
        return int(batch["cloudiway_batch_id"])

    client = await _cloudiway_client_ready()
    name = batch["batch_name"]

    try:
        created = await client.create_mail_batch(name)
        cloud_batch_id = _extract_cloudiway_batch_id(created, name)
        if not cloud_batch_id:
            existing = await client.mail_batches()
            cloud_batch_id = _extract_cloudiway_batch_id(existing, name)
        if not cloud_batch_id:
            raise RuntimeError(
                f"Cloudiway batch '{name}' was submitted but no batch ID could be resolved"
            )

        with conn() as db:
            db.execute(
                """UPDATE migration_batches
                   SET cloudiway_batch_id=?,cloudiway_batch_name=?,
                       workflow_status=CASE
                           WHEN workflow_status='cloudiway_batch_error' AND ? IN ('existing_password','existing_password_retry') THEN 'ready_for_cloudiway'
                           WHEN workflow_status='cloudiway_batch_error' THEN 'identity_pending'
                           ELSE workflow_status
                       END,
                       last_error=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (cloud_batch_id, name, batch.get("workflow_mode") or "", migration_batch_id),
            )
        log_event(
            None,
            "cloudiway_migration_batch_created",
            f"Migration batch {migration_batch_id} mapped to Cloudiway batch {cloud_batch_id} ({name})",
        )
        return cloud_batch_id
    except Exception as exc:
        with conn() as db:
            db.execute(
                """UPDATE migration_batches
                   SET workflow_status='cloudiway_batch_error',last_error=?,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (str(exc)[:3000], migration_batch_id),
            )
        log_event(
            None,
            "cloudiway_migration_batch_failed",
            f"Migration batch {migration_batch_id}: {exc}",
        )
        raise


async def assign_migration_batch_members(migration_batch_id: int, object_ids: list[int]) -> int:
    if not object_ids:
        raise RuntimeError("No Cloudiway object IDs were supplied for batch assignment")
    cloud_batch_id = await ensure_migration_cloudiway_batch(migration_batch_id)
    client = await _cloudiway_client_ready()
    await client.add_mail_batch_members(cloud_batch_id, object_ids)
    with conn() as db:
        db.execute(
            """UPDATE migration_batches
               SET workflow_status='cloudiway_members_assigned',last_error=NULL,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (migration_batch_id,),
        )
    log_event(
        None,
        "cloudiway_migration_batch_members_assigned",
        f"Assigned {len(object_ids)} user(s) to Cloudiway batch {cloud_batch_id}",
    )
    return cloud_batch_id


async def ensure_upload_cloudiway_batch(upload_batch_id: int) -> int:
    """Ensure every application upload has a corresponding Cloudiway Mail Batch."""
    with conn() as db:
        batch = db.execute(
            "SELECT * FROM upload_batches WHERE id=?",
            (upload_batch_id,),
        ).fetchone()
    if not batch:
        raise RuntimeError(f"Upload batch {upload_batch_id} was not found")
    if batch.get("cloudiway_batch_id"):
        return int(batch["cloudiway_batch_id"])

    client = await _cloudiway_client_ready()
    name = batch["batch_name"]

    try:
        created = await client.create_mail_batch(name)
        batch_id = _extract_cloudiway_batch_id(created, name)
        if not batch_id:
            existing = await client.mail_batches()
            batch_id = _extract_cloudiway_batch_id(existing, name)
        if not batch_id:
            raise RuntimeError(
                f"Cloudiway batch '{name}' was submitted but no batch ID could be resolved"
            )

        with conn() as db:
            db.execute(
                """UPDATE upload_batches
                   SET cloudiway_batch_id=?,cloudiway_batch_name=?,
                       workflow_status=CASE
                           WHEN workflow_status='cloudiway_batch_error' THEN 'passwords_generated'
                           WHEN workflow_status='uploaded' THEN 'cloudiway_batch_created'
                           ELSE workflow_status
                       END,
                       last_error=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (batch_id, name, upload_batch_id),
            )
        log_event(
            None,
            "cloudiway_upload_batch_created",
            f"Upload batch {upload_batch_id} mapped to Cloudiway batch {batch_id} ({name})",
        )
        return batch_id
    except Exception as exc:
        with conn() as db:
            db.execute(
                """UPDATE upload_batches
                   SET workflow_status='cloudiway_batch_error',last_error=?,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (str(exc)[:3000], upload_batch_id),
            )
        log_event(
            None,
            "cloudiway_upload_batch_failed",
            f"Upload batch {upload_batch_id}: {exc}",
        )
        raise


async def assign_upload_batch_members(upload_batch_id: int, object_ids: list[int]) -> int:
    if not object_ids:
        raise RuntimeError("No Cloudiway object IDs were supplied for batch assignment")
    cloud_batch_id = await ensure_upload_cloudiway_batch(upload_batch_id)
    client = await _cloudiway_client_ready()
    await client.add_mail_batch_members(cloud_batch_id, object_ids)
    with conn() as db:
        db.execute(
            """UPDATE upload_batches
               SET workflow_status='cloudiway_members_assigned',last_error=NULL,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (upload_batch_id,),
        )
    log_event(
        None,
        "cloudiway_batch_members_assigned",
        f"Assigned {len(object_ids)} user(s) to Cloudiway batch {cloud_batch_id}",
    )
    return cloud_batch_id


async def _validate_cloudiway_user_mapping(
    client: CloudiwayClient,
    object_id: int,
    expected_source: str,
    expected_target: str,
) -> dict:
    """Pull Cloudiway's stored mailbox mapping and reject a wrong target before migration."""
    remote = await client.get_mail_user(object_id)
    record = remote.get("responseData") if isinstance(remote, dict) else None
    if not isinstance(record, dict):
        record = remote if isinstance(remote, dict) else {}

    remote_source = str(record.get("sourceEmail") or "").strip()
    remote_target = str(record.get("targetEmail") or "").strip()
    exchange_guid = str(record.get("exchangeGuid") or "").strip()
    identity = str(record.get("identity") or "").strip()

    if remote_source and remote_source.lower() != expected_source.lower():
        raise RuntimeError(
            f"Cloudiway source mapping mismatch: app={expected_source}, Cloudiway={remote_source}"
        )
    if remote_target and remote_target.lower() != expected_target.lower():
        raise RuntimeError(
            f"Cloudiway target mapping mismatch: app={expected_target}, Cloudiway={remote_target}. "
            "Correct the Cloudiway mail user mapping before starting migration."
        )

    return {
        "sourceEmail": remote_source or expected_source,
        "targetEmail": remote_target or expected_target,
        "exchangeGuid": exchange_guid,
        "identity": identity,
        "targetRecipientType": record.get("targetRecipientType"),
    }


async def ensure_cloudiway_user(user: dict) -> int:
    client = await _cloudiway_client_ready()
    source_pool = get_setting("cloudiway_source_pool_id")
    target_pool = get_setting("cloudiway_target_pool_id")
    if not source_pool or not target_pool:
        raise RuntimeError("Select the Cloudiway source and target connector pools first")

    if user.get("cloudiway_object_id"):
        object_id = int(user["cloudiway_object_id"])
        mapping = await _validate_cloudiway_user_mapping(
            client, object_id, user["source_email"], user["target_email"]
        )
        log_event(
            user["id"],
            "cloudiway_mapping_verified",
            "Cloudiway mapping verified before migration: "
            + json.dumps(mapping, default=str)[:1200],
        )
        return object_id

    try:
        found = await client.verify_mail_user(user["source_email"])
        object_id = _extract_object_id(found)
        if object_id:
            with conn() as db:
                db.execute(
                    "UPDATE users SET cloudiway_object_id=?,cloudiway_status='existing',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (object_id, user["id"]),
                )
            mapping = await _validate_cloudiway_user_mapping(
                client, object_id, user["source_email"], user["target_email"]
            )
            log_event(
                user["id"],
                "cloudiway_user_found",
                "Existing Cloudiway mail user found and mapping verified: "
                + json.dumps(mapping, default=str)[:1200],
            )
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
    mapping = await _validate_cloudiway_user_mapping(
        client, object_id, user["source_email"], user["target_email"]
    )
    with conn() as db:
        db.execute(
            "UPDATE users SET cloudiway_object_id=?,cloudiway_status='created',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (object_id, user["id"]),
        )
    log_event(
        user["id"],
        "cloudiway_mapping_verified",
        "Cloudiway mapping verified after user creation: "
        + json.dumps(mapping, default=str)[:1200],
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

        username = str(user["source_email"]).strip().lower()
        log_event(
            user_id,
            "cloudiway_credential_payload",
            f"Registering Cloudiway source credentials: username={username}; "
            f"password_source=generated_or_reset; password_length={len(password)}",
        )
        await cloud.register_source_credentials(token, username, password)
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
    _cloudiway_preflight()


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

            if status in ("failed", "attention"):
                effective_code = issue_code or (
                    "cloudiway_status_attention" if status == "attention" else "cloudiway_status_failed"
                )
                record_user_issue(
                    int(row["id"]),
                    effective_code,
                    error_message or "Cloudiway returned a migration issue requiring review.",
                )
            elif status in ("migrating", "completed"):
                clear_user_issue(
                    int(row["id"]),
                    "Cloudiway migration is running normally." if status == "migrating" else "Cloudiway migration completed.",
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
        with conn() as db:
            timed_out_rows = db.execute(
                "SELECT id FROM users WHERE migration_status='timed_out' AND cloudiway_status='timed_out'"
            ).fetchall()
        for timed_row in timed_out_rows:
            record_user_issue(
                int(timed_row["id"]),
                "timed_out",
                "Migration exceeded the configured timeout; review Cloudiway before retrying.",
            )
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

    refresh_upload_batch_states()

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

    credential_markers = (
        "invalid credential",
        "invalid credentials",
        "authentication failed",
        "authenticationfailed",
        "login failed",
        "invalid password",
        "incorrect password",
        "username or password",
        "auth failed",
        "imap authentication failed",
    )
    if any(marker in combined for marker in credential_markers):
        return (
            "failed",
            "mailbox_authentication_failed",
            "Mailbox authentication failed. Verify the source password/credentials and connector access.",
        )

    if "cannot connect imap client" in combined:
        return (
            "failed",
            "source_imap_connection_failed",
            "Cloudiway could not connect to the source IMAP mailbox. Verify the source mailbox credentials and the IMAP connector host, port, and TLS settings before retrying.",
        )

    if "unable to connect to mailbox in the source" in combined:
        return (
            "failed",
            "source_mailbox_connection_failed",
            "Cloudiway could not open the source Rackspace mailbox. "
            "Verify the source mailbox exists and that the generated password was applied.",
        )

    return None, None, None


ISSUE_CATEGORY_LABELS = {
    "credentials": "Password / Credentials",
    "target_mailbox": "Microsoft 365 Target Mailbox",
    "source_mailbox": "Rackspace Source Mailbox",
    "source_connectivity": "Source IMAP / Connectivity",
    "ad_identity": "AD Identity Review",
    "provisioning": "AD / M365 Provisioning",
    "timeout": "Migration Timeout",
    "cloudiway": "Cloudiway Status",
    "other": "Other / Unclassified",
}


def issue_category_for_code(issue_code: str | None) -> str:
    mapping = {
        "mailbox_authentication_failed": "credentials",
        "target_mailbox_missing": "target_mailbox",
        "target_mailbox_connection_failed": "target_mailbox",
        "source_mailbox_connection_failed": "source_mailbox",
        "source_imap_connection_failed": "source_connectivity",
        "timed_out": "timeout",
        "ad_identity_conflict": "ad_identity",
        "ad_manual_review": "ad_identity",
        "provisioning_failed": "provisioning",
        "cloudiway_status_attention": "cloudiway",
        "cloudiway_status_failed": "cloudiway",
    }
    return mapping.get(issue_code or "", "other")


def _issue_recovery_settings() -> tuple[bool, int, int]:
    enabled = (get_setting("issue_auto_recovery_enabled") or "1") == "1"
    try:
        delay_minutes = max(1, int(get_setting("issue_credential_retry_delay_minutes") or "3"))
    except Exception:
        delay_minutes = 3
    try:
        max_attempts = max(1, min(10, int(get_setting("issue_credential_retry_max") or "2")))
    except Exception:
        max_attempts = 2
    return enabled, delay_minutes, max_attempts


def record_user_issue(
    user_id: int,
    issue_code: str,
    message: str,
    *,
    category: str | None = None,
) -> None:
    """Persist one current actionable issue for the user.

    Credential failures can be scheduled for automatic recovery when a stored
    source credential is available. Other categories are classified for the
    issue dashboard and held for the appropriate manual/background workflow.
    """
    category = category or issue_category_for_code(issue_code)
    enabled, delay_minutes, max_attempts = _issue_recovery_settings()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    with conn() as db:
        row = db.execute(
            """SELECT issue_code,issue_status,auto_recovery_attempts,auto_recovery_next_at,
                      auto_recovery_status,cloudiway_object_id,provisioning_profile_id,batch_number,
                      source_credential_password_enc,generated_password_enc
               FROM users WHERE id=?""",
            (user_id,),
        ).fetchone()
        if not row:
            return

        same_issue = row.get("issue_code") == issue_code and row.get("issue_status") not in (None, "", "none", "resolved")
        attempts = int(row.get("auto_recovery_attempts") or 0) if same_issue else 0
        credential_available = bool(
            row.get("source_credential_password_enc") or row.get("generated_password_enc")
        )

        auto_eligible = (
            enabled
            and attempts < max_attempts
            and (
                (
                    category == "credentials"
                    and credential_available
                    and bool(row.get("cloudiway_object_id"))
                )
                or (
                    category == "target_mailbox"
                    and issue_code == "target_mailbox_missing"
                    and bool(row.get("cloudiway_object_id"))
                    and bool(row.get("provisioning_profile_id"))
                )
                or (
                    category == "cloudiway"
                    and issue_code == "cloudiway_submission_failed"
                    and bool(row.get("batch_number"))
                )
            )
        )
        manual_required = not auto_eligible
        issue_status = "open" if auto_eligible else "manual_required"
        auto_status = "scheduled" if auto_eligible else "manual_required"
        next_at = now + timedelta(minutes=delay_minutes) if auto_eligible else None

        if same_issue and auto_eligible and row.get("auto_recovery_next_at"):
            # Do not keep moving the due time forward on every status poll.
            next_at = row.get("auto_recovery_next_at")
            auto_status = row.get("auto_recovery_status") or auto_status

        if same_issue and row.get("issue_status") == "recovering" and attempts < max_attempts:
            # A restarted job has not yet had time to prove success/failure.
            issue_status = "recovering"
            auto_status = "monitoring"
            next_at = row.get("auto_recovery_next_at") or (
                now + timedelta(minutes=delay_minutes)
            )
            manual_required = False

        db.execute(
            """UPDATE users
               SET issue_code=?,issue_category=?,issue_status=?,
                   issue_detected_at=COALESCE(issue_detected_at,CURRENT_TIMESTAMP),
                   issue_last_seen_at=CURRENT_TIMESTAMP,
                   manual_action_required=?,
                   auto_recovery_attempts=?,
                   auto_recovery_status=?,
                   auto_recovery_next_at=?,
                   error_message=?,
                   updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                issue_code,
                category,
                issue_status,
                1 if manual_required else 0,
                attempts,
                auto_status,
                next_at,
                message[:3000],
                user_id,
            ),
        )


def clear_user_issue(user_id: int, reason: str = "") -> None:
    with conn() as db:
        row = db.execute(
            "SELECT issue_code,issue_status FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        if not row:
            return
        had_issue = bool(row.get("issue_code")) and row.get("issue_status") not in ("none", "resolved")
        db.execute(
            """UPDATE users
               SET issue_code=NULL,issue_category=NULL,issue_status='resolved',
                   manual_action_required=0,auto_recovery_attempts=0,
                   auto_recovery_status='resolved',auto_recovery_next_at=NULL,
                   updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (user_id,),
        )
    if had_issue:
        log_event(
            user_id,
            "issue_resolved",
            reason or "Previously detected migration issue is no longer present.",
        )


async def recover_credential_issue(user_id: int, *, force: bool = False) -> dict:
    """Re-push a stored source password and restart the same Cloudiway object."""
    enabled, delay_minutes, max_attempts = _issue_recovery_settings()
    if not enabled and not force:
        return {"recovered": False, "reason": "Automatic issue recovery is disabled"}

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return {"recovered": False, "reason": "User not found"}
    user = dict(row)

    if not user.get("cloudiway_object_id"):
        record_user_issue(
            user_id,
            "cloudiway_user_missing",
            "No Cloudiway object ID exists for this user. Manual review is required.",
            category="cloudiway",
        )
        return {"recovered": False, "reason": "No Cloudiway object ID"}

    attempts = int(user.get("auto_recovery_attempts") or 0)
    if attempts >= max_attempts and not force:
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET issue_status='manual_required',manual_action_required=1,
                       auto_recovery_status='exhausted',auto_recovery_next_at=NULL,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (user_id,),
            )
        return {"recovered": False, "reason": "Automatic credential retries exhausted"}

    cloud = await _cloudiway_client_ready()
    object_id = int(user["cloudiway_object_id"])

    # Re-check live Cloudiway state immediately before making a write.
    progress = await cloud.progress(object_id, max(1, settings.progress_window_minutes))
    remote_status, percent, detail = parse_progress(progress)
    logs_data = None
    if remote_status in ("failed", "attention"):
        try:
            logs_data = await cloud.logs(object_id)
        except Exception as exc:
            log_event(user_id, "cloudiway_logs_fetch_failed", str(exc))

    _, current_issue_code, current_message = classify_cloudiway_issue(progress, logs_data)

    if remote_status == "completed":
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET migration_status='completed',cloudiway_status='completed',
                       progress_percent=?,progress_detail=?,error_message=NULL,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (percent, detail, user_id),
            )
        clear_user_issue(user_id, "Cloudiway reports the migration as completed.")
        return {"recovered": False, "resolved": True, "reason": "Already completed"}

    if remote_status == "migrating":
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET migration_status='migrating',cloudiway_status='migrating',
                       progress_percent=?,progress_detail=?,error_message=NULL,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (percent, detail, user_id),
            )
        clear_user_issue(user_id, "Cloudiway reports the migration is running.")
        return {"recovered": False, "resolved": True, "reason": "Already migrating"}

    if current_issue_code != "mailbox_authentication_failed" and not force:
        if current_issue_code:
            record_user_issue(
                user_id,
                current_issue_code,
                current_message or "Cloudiway returned a different issue during recovery.",
            )
        return {
            "recovered": False,
            "reason": "The current Cloudiway issue is not an explicit credential failure",
        }

    username, password, credential_origin = _source_credentials_for_cloudiway(user)
    token = await cloud.get_self_service_token(object_id)
    await cloud.register_source_credentials(token, username, password)
    await cloud.restart_migration(object_id)

    new_attempts = attempts + 1
    next_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=delay_minutes)
    with conn() as db:
        db.execute(
            """UPDATE users
               SET migration_status='migrating',
                   cloudiway_status='auto_credential_recovery_restarted',
                   issue_code='mailbox_authentication_failed',
                   issue_category='credentials',
                   issue_status='recovering',
                   manual_action_required=0,
                   auto_recovery_attempts=?,
                   auto_recovery_status='restarted',
                   auto_recovery_last_at=CURRENT_TIMESTAMP,
                   auto_recovery_next_at=?,
                   error_message=?,
                   batch_started_at=COALESCE(batch_started_at,CURRENT_TIMESTAMP),
                   updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                new_attempts,
                next_at,
                f"Credential error detected. Stored source credential was pushed to Cloudiway again and the existing migration was restarted automatically (attempt {new_attempts}/{max_attempts}).",
                user_id,
            ),
        )
    log_event(
        user_id,
        "automatic_credential_recovery",
        f"Credential issue auto-recovery attempt {new_attempts}/{max_attempts}: "
        f"username={username}; credential_source={credential_origin}; Cloudiway object={object_id}; same object restarted.",
    )
    return {
        "recovered": True,
        "attempt": new_attempts,
        "max_attempts": max_attempts,
        "object_id": object_id,
    }


def sync_local_issue_states() -> None:
    """Surface AD/provisioning issues in the same issue center."""
    with conn() as db:
        ad_rows = db.execute(
            """SELECT id,ad_conflict_reason FROM users
               WHERE ad_match_status IN ('manual_review','conflict','identity_conflict')
                 AND migration_status IN ('waiting','preparing','ready')"""
        ).fetchall()
        provisioning_rows = db.execute(
            """SELECT id,provisioning_error FROM users
               WHERE provisioning_error IS NOT NULL AND provisioning_error<>''
                 AND provisioning_status NOT IN ('m365_ready','bypassed')
                 AND migration_status IN ('waiting','preparing','ready')"""
        ).fetchall()
        uncategorized = db.execute(
            """SELECT id,migration_status,cloudiway_object_id,error_message
               FROM users
               WHERE migration_status IN ('failed','attention','timed_out')
                 AND (issue_code IS NULL OR issue_status IN ('none','resolved'))
                 AND error_message IS NOT NULL AND error_message<>''"""
        ).fetchall()

    for row in ad_rows:
        record_user_issue(
            int(row["id"]),
            "ad_manual_review",
            row.get("ad_conflict_reason") or "Active Directory identity requires manual review.",
            category="ad_identity",
        )
    for row in provisioning_rows:
        record_user_issue(
            int(row["id"]),
            "provisioning_failed",
            row.get("provisioning_error") or "AD/Microsoft 365 provisioning requires review.",
            category="provisioning",
        )

    for row in uncategorized:
        uid = int(row["id"])
        message = str(row.get("error_message") or "")
        if row.get("migration_status") == "timed_out":
            record_user_issue(uid, "timed_out", message, category="timeout")
            continue
        status_override, issue_code, friendly = classify_cloudiway_issue(
            {"status": row.get("migration_status")},
            {"logs": [message]},
        )
        if issue_code:
            record_user_issue(uid, issue_code, friendly or message)
        elif not row.get("cloudiway_object_id"):
            record_user_issue(
                uid,
                "cloudiway_submission_failed",
                message or "The user did not reach Cloudiway successfully.",
                category="cloudiway",
            )
        else:
            record_user_issue(
                uid,
                "cloudiway_status_failed" if row.get("migration_status") == "failed" else "cloudiway_status_attention",
                message or "Migration requires review.",
                category="cloudiway",
            )


async def recover_target_mailbox_issue(user_id: int) -> dict:
    """Re-check M365 mailbox readiness and restart the same Cloudiway job when ready."""
    enabled, delay_minutes, max_attempts = _issue_recovery_settings()
    if not enabled:
        return {"recovered": False, "reason": "Automatic issue recovery is disabled"}

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return {"recovered": False, "reason": "User not found"}
    user = dict(row)

    if not user.get("cloudiway_object_id"):
        return {"recovered": False, "reason": "No Cloudiway object ID"}
    if not user.get("provisioning_profile_id"):
        with conn() as db:
            db.execute(
                """UPDATE users SET issue_status='manual_required',
                   manual_action_required=1,auto_recovery_status='manual_required',
                   auto_recovery_next_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (user_id,),
            )
        return {"recovered": False, "reason": "No M365 provisioning profile is linked to this user"}

    attempts = int(user.get("auto_recovery_attempts") or 0)
    if attempts >= max_attempts:
        with conn() as db:
            db.execute(
                """UPDATE users SET issue_status='manual_required',
                   manual_action_required=1,auto_recovery_status='exhausted',
                   auto_recovery_next_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (user_id,),
            )
        return {"recovered": False, "reason": "Automatic target-mailbox retries exhausted"}

    from app.provisioning import refresh_m365_user

    readiness = await refresh_m365_user(user_id)
    if readiness.get("mailbox") != "ready":
        next_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=delay_minutes)
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET issue_status='open',manual_action_required=0,
                       auto_recovery_status='waiting_for_mailbox',
                       auto_recovery_next_at=?,updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (next_at, user_id),
            )
        log_event(
            user_id,
            "target_mailbox_still_pending",
            "Microsoft 365 mailbox is not ready yet; background recovery will check again.",
        )
        return {"recovered": False, "waiting": True, "reason": "Target mailbox is still provisioning"}

    cloud = await _cloudiway_client_ready()
    object_id = int(user["cloudiway_object_id"])
    await cloud.restart_migration(object_id)

    new_attempts = attempts + 1
    next_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=delay_minutes)
    with conn() as db:
        db.execute(
            """UPDATE users
               SET migration_status='migrating',
                   cloudiway_status='auto_target_mailbox_restarted',
                   issue_status='recovering',manual_action_required=0,
                   auto_recovery_attempts=?,auto_recovery_status='restarted',
                   auto_recovery_last_at=CURRENT_TIMESTAMP,auto_recovery_next_at=?,
                   error_message=?,
                   updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                new_attempts,
                next_at,
                f"Microsoft 365 mailbox became ready. Existing Cloudiway migration restarted automatically (attempt {new_attempts}/{max_attempts}).",
                user_id,
            ),
        )
    log_event(
        user_id,
        "automatic_target_mailbox_recovery",
        f"Target mailbox became ready; restarted existing Cloudiway object {object_id} (attempt {new_attempts}/{max_attempts}).",
    )
    return {
        "recovered": True,
        "attempt": new_attempts,
        "max_attempts": max_attempts,
        "object_id": object_id,
    }


async def recover_cloudiway_submission_issue(user_id: int) -> dict:
    """Retry a user that failed before it was successfully submitted/prepared in Cloudiway.

    Automatic recovery is intentionally limited to workflows that do not perform
    a new live Rackspace password reset. The automatic Rackspace-API workflow is
    held for manual review because retrying it could change the mailbox password
    again.
    """
    enabled, delay_minutes, max_attempts = _issue_recovery_settings()
    if not enabled:
        return {"recovered": False, "reason": "Automatic issue recovery is disabled"}

    with conn() as db:
        user_row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user_row:
            return {"recovered": False, "reason": "User not found"}
        user = dict(user_row)
        if not user.get("batch_number"):
            return {"recovered": False, "reason": "User is not linked to a migration batch"}
        batch = db.execute(
            """SELECT mb.*,ub.workflow_mode
               FROM migration_batches mb
               JOIN upload_batches ub ON ub.id=mb.upload_batch_id
               WHERE mb.id=?""",
            (int(user["batch_number"]),),
        ).fetchone()

    if not batch:
        return {"recovered": False, "reason": "Migration batch not found"}

    workflow_mode = str(batch.get("workflow_mode") or "")
    if workflow_mode in ("automatic", "existing_password_retry"):
        with conn() as db:
            db.execute(
                """UPDATE users SET issue_status='manual_required',
                   manual_action_required=1,auto_recovery_status='manual_required',
                   auto_recovery_next_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (user_id,),
            )
        return {
            "recovered": False,
            "reason": "This workflow requires manual review before retrying submission",
        }

    attempts = int(user.get("auto_recovery_attempts") or 0)
    if attempts >= max_attempts:
        with conn() as db:
            db.execute(
                """UPDATE users SET issue_status='manual_required',
                   manual_action_required=1,auto_recovery_status='exhausted',
                   auto_recovery_next_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (user_id,),
            )
        return {"recovered": False, "reason": "Automatic submission retries exhausted"}

    if workflow_mode == "manual_bulk":
        if user.get("rackspace_status") != "manual_confirmed":
            with conn() as db:
                db.execute(
                    """UPDATE users SET issue_status='manual_required',
                       manual_action_required=1,auto_recovery_status='manual_required',
                       auto_recovery_next_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (user_id,),
                )
            return {"recovered": False, "reason": "Rackspace password confirmation is required"}
        object_id = await prepare_manual_user(user_id)
    elif workflow_mode == "existing_password":
        object_id = await prepare_existing_password_user(user_id)
    else:
        return {"recovered": False, "reason": f"Workflow mode {workflow_mode!r} is not safe for automatic submission retry"}

    cloud = await _cloudiway_client_ready()
    cloud_batch_id = batch.get("cloudiway_batch_id")
    if cloud_batch_id:
        await cloud.add_mail_batch_members(int(cloud_batch_id), [int(object_id)])

    should_start = batch.get("workflow_status") == "migrating" or int(batch.get("auto_start") or 0) == 1
    if should_start:
        await cloud.start_migration([int(object_id)])
        migration_status = "migrating"
        cloud_status = "auto_submission_recovered_started"
    else:
        migration_status = "ready"
        cloud_status = "auto_submission_recovered_ready"

    new_attempts = attempts + 1
    next_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=delay_minutes)
    with conn() as db:
        db.execute(
            """UPDATE users
               SET cloudiway_object_id=?,cloudiway_status=?,migration_status=?,
                   issue_status=?,manual_action_required=0,
                   auto_recovery_attempts=?,auto_recovery_status='submission_retried',
                   auto_recovery_last_at=CURRENT_TIMESTAMP,auto_recovery_next_at=?,
                   error_message=NULL,updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                int(object_id),
                cloud_status,
                migration_status,
                "recovering" if should_start else "resolved",
                new_attempts,
                next_at if should_start else None,
                user_id,
            ),
        )

    log_event(
        user_id,
        "automatic_cloudiway_submission_recovery",
        f"Retried Cloudiway preparation for workflow={workflow_mode}; object={object_id}; "
        f"batch={cloud_batch_id or 'none'}; started={should_start}; attempt={new_attempts}/{max_attempts}.",
    )
    if not should_start:
        clear_user_issue(
            user_id,
            "Cloudiway preparation succeeded after an automatic retry; user is ready for the batch to start.",
        )
    return {
        "recovered": True,
        "object_id": int(object_id),
        "started": should_start,
        "attempt": new_attempts,
    }


async def process_background_issues() -> dict:
    """Handle actionable issues independently of the administrator web session."""
    enabled, _, max_attempts = _issue_recovery_settings()
    summary = {"checked": 0, "recovered": 0, "resolved": 0, "manual": 0, "errors": 0}
    sync_local_issue_states()
    if not enabled or not get_setting("cloudiway_token"):
        return summary

    with conn() as db:
        rows = db.execute(
            """SELECT id FROM users
               WHERE issue_category IN ('credentials','target_mailbox','cloudiway')
                 AND issue_status IN ('open','recovering')
                 AND manual_action_required=0
                 AND auto_recovery_attempts < ?
                 AND (auto_recovery_next_at IS NULL OR auto_recovery_next_at <= UTC_TIMESTAMP())
               ORDER BY COALESCE(auto_recovery_next_at,issue_detected_at),id
               LIMIT 25""",
            (max_attempts,),
        ).fetchall()

    for row in rows:
        uid = int(row["id"])
        summary["checked"] += 1
        try:
            with conn() as db:
                issue_row = db.execute(
                    "SELECT issue_category,issue_code FROM users WHERE id=?",
                    (uid,),
                ).fetchone()
            if issue_row and issue_row.get("issue_category") == "target_mailbox" and issue_row.get("issue_code") == "target_mailbox_missing":
                result = await recover_target_mailbox_issue(uid)
            elif issue_row and issue_row.get("issue_category") == "cloudiway" and issue_row.get("issue_code") == "cloudiway_submission_failed":
                result = await recover_cloudiway_submission_issue(uid)
            else:
                result = await recover_credential_issue(uid)
            if result.get("recovered"):
                summary["recovered"] += 1
            elif result.get("resolved"):
                summary["resolved"] += 1
            elif "exhausted" in str(result.get("reason") or "").lower():
                summary["manual"] += 1
        except Exception as exc:
            summary["errors"] += 1
            log_event(uid, "automatic_issue_recovery_failed", str(exc))
            with conn() as db:
                current = db.execute(
                    "SELECT auto_recovery_attempts FROM users WHERE id=?",
                    (uid,),
                ).fetchone()
                attempts = int(current["auto_recovery_attempts"] or 0) if current else 0
                if attempts >= max_attempts:
                    db.execute(
                        """UPDATE users
                           SET issue_status='manual_required',manual_action_required=1,
                               auto_recovery_status='exhausted',auto_recovery_next_at=NULL,
                               updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                        (uid,),
                    )
    return summary


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

    username, password, credential_origin = _source_credentials_for_cloudiway(user)
    cloud = await _cloudiway_client_ready()
    object_id = await ensure_cloudiway_user(user)
    token = await cloud.get_self_service_token(object_id)
    log_event(
        user_id,
        "cloudiway_credential_payload",
        f"Registering Cloudiway source credentials: username={username}; "
        f"password_source={credential_origin}; password_length={len(password)}",
    )
    await cloud.register_source_credentials(token, username, password)

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


def _source_credentials_for_cloudiway(user: dict) -> tuple[str, str, str]:
    """Return the exact source username/password that will be sent to Cloudiway.

    Username is always the full source email address. Existing-password uploads
    use the dedicated encrypted upload credential; generated/reset workflows use
    the generated password field.
    """
    username = str(user.get("source_email") or "").strip().lower()
    if not username or "@" not in username:
        raise RuntimeError("Cloudiway source username must be the full source email address")

    method = user.get("password_reset_method") or ""
    if method in ("existing_password", "existing_password_retry"):
        stored_username = str(user.get("source_credential_username") or "").strip().lower()
        if stored_username and stored_username != username:
            raise RuntimeError(
                f"Stored source credential username '{stored_username}' does not match source email '{username}'"
            )
        encrypted = user.get("source_credential_password_enc")
        # Backward-compatible fallback for rows created before the dedicated
        # source credential columns were added.
        if not encrypted:
            encrypted = user.get("generated_password_enc")
        if not encrypted:
            raise RuntimeError("No uploaded existing source password is stored for this user")
        return username, decrypt_secret(encrypted), "uploaded_excel"

    encrypted = user.get("generated_password_enc")
    if not encrypted:
        raise RuntimeError("No generated/reset source password is stored for this user")
    return username, decrypt_secret(encrypted), "generated_or_reset"


async def find_existing_cloudiway_user(user: dict) -> int | None:
    """Resolve an existing Cloudiway mail user without creating a new object."""
    client = await _cloudiway_client_ready()

    if user.get("cloudiway_object_id"):
        object_id = int(user["cloudiway_object_id"])
        mapping = await _validate_cloudiway_user_mapping(
            client, object_id, user["source_email"], user["target_email"]
        )
        log_event(
            user["id"],
            "cloudiway_recovery_mapping_verified",
            "Recovery workflow verified existing Cloudiway object: "
            + json.dumps(mapping, default=str)[:1200],
        )
        return object_id

    try:
        found = await client.verify_mail_user(user["source_email"])
        object_id = _extract_object_id(found)
        if not object_id:
            return None
        mapping = await _validate_cloudiway_user_mapping(
            client, object_id, user["source_email"], user["target_email"]
        )
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET cloudiway_object_id=?,cloudiway_status='existing',
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (object_id, user["id"]),
            )
        log_event(
            user["id"],
            "cloudiway_recovery_user_found",
            "Recovery workflow found existing Cloudiway object and verified mapping: "
            + json.dumps(mapping, default=str)[:1200],
        )
        return object_id
    except Exception as exc:
        message = str(exc)
        log_event(user["id"], "cloudiway_recovery_lookup_failed", message)
        if "(401)" in message or "(403)" in message:
            raise
        return None


async def prepare_existing_password_user(user_id: int) -> int:
    """Register an uploaded source password and safely handle existing Cloudiway state.

    existing_password:
      - creates/reuses the Cloudiway user and prepares a normal direct migration.
    existing_password_retry:
      - requires an existing Cloudiway user;
      - if Cloudiway reports failed/attention, pushes the supplied password again and
        marks the same object for Restart;
      - running/completed objects are left alone and never duplicated/restarted.
    """
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise RuntimeError(f"User {user_id} not found")
    user = dict(row)

    method = user.get("password_reset_method") or ""
    if method not in ("existing_password", "existing_password_retry"):
        raise RuntimeError("User is not assigned to an existing-password Cloudiway workflow")

    recovery_only = method == "existing_password_retry"
    prior_local_status = str(user.get("migration_status") or "").strip().lower()
    username, password, credential_origin = _source_credentials_for_cloudiway(user)
    cloud = await _cloudiway_client_ready()

    if recovery_only:
        object_id = await find_existing_cloudiway_user(user)
        if not object_id:
            raise RuntimeError(
                f"No existing Cloudiway mail user was found for {username}. "
                "Use the normal Existing source password workflow for a new Cloudiway migration."
            )
    else:
        object_id = await ensure_cloudiway_user(user)

    remote_status = None
    remote_detail = None
    try:
        progress = await cloud.progress(object_id, max(1, settings.progress_window_minutes))
        remote_status, _, remote_detail = parse_progress(progress)
    except Exception as exc:
        remote_detail = f"Progress lookup unavailable: {exc}"

    # Recovery mode is deliberately state-aware. Running/completed jobs are not
    # touched merely because their row was uploaded again.
    if recovery_only and remote_status == "completed":
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET cloudiway_object_id=?,cloudiway_status='existing_completed',
                       migration_status='completed',error_message=NULL,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (object_id, user_id),
            )
        log_event(
            user_id,
            "cloudiway_recovery_skipped_completed",
            f"Recovery upload found completed Cloudiway object {object_id}; password was not re-pushed and job was not restarted.",
        )
        return object_id

    if recovery_only and remote_status == "migrating":
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET cloudiway_object_id=?,cloudiway_status='existing_migrating',
                       migration_status='migrating',error_message=NULL,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (object_id, user_id),
            )
        log_event(
            user_id,
            "cloudiway_recovery_skipped_running",
            f"Recovery upload found Cloudiway object {object_id} already migrating; password was not re-pushed and job was not restarted.",
        )
        return object_id

    # A live running/completed Cloudiway status always wins over stale local
    # error state. Only fall back to the local terminal state when Cloudiway did
    # not return a definitive running/completed status.
    should_restart = (
        remote_status in ("failed", "attention")
        or (
            remote_status not in ("migrating", "completed")
            and prior_local_status in ("failed", "attention", "timed_out")
        )
    )

    if recovery_only and not should_restart:
        raise RuntimeError(
            f"Existing Cloudiway object {object_id} was found, but it is not in a failed/attention state "
            f"(remote_status={remote_status or 'unknown'}). Recovery mode will not restart it blindly."
        )

    token = await cloud.get_self_service_token(object_id)
    log_event(
        user_id,
        "cloudiway_credential_payload",
        f"Registering Cloudiway source credentials: username={username}; "
        f"password_source={credential_origin}; password_length={len(password)}",
    )
    await cloud.register_source_credentials(token, username, password)

    if remote_status == "completed":
        next_cloud_status = "existing_completed"
        next_migration_status = "completed"
        action = "credentials_refreshed_existing_completed"
    elif remote_status == "migrating":
        next_cloud_status = "existing_migrating"
        next_migration_status = "migrating"
        action = "credentials_refreshed_existing_migrating"
    elif should_restart:
        next_cloud_status = "restart_required"
        next_migration_status = "ready"
        action = "credentials_refreshed_restart_required"
    else:
        next_cloud_status = "credentials_set"
        next_migration_status = "ready"
        action = "credentials_refreshed_ready_to_start"

    with conn() as db:
        db.execute(
            """UPDATE users
               SET cloudiway_object_id=?,
                   cloudiway_status=?,
                   rackspace_status='existing_password',
                   provisioning_status='bypassed',
                   ad_match_status='bypassed',
                   entra_status='bypassed',
                   license_status='bypassed',
                   mailbox_status='bypassed',
                   migration_status=?,
                   error_message=NULL,
                   updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (object_id, next_cloud_status, next_migration_status, user_id),
        )

    log_event(
        user_id,
        action,
        "Existing Cloudiway object reused; uploaded source password pushed again. "
        f"recovery_only={recovery_only}; remote_status={remote_status or 'unknown'}; "
        f"object_id={object_id}; detail={str(remote_detail)[:700]}",
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


async def prepare_migration_batch(migration_batch_id: int) -> dict:
    """Prepare only the users selected into one incremental migration batch."""
    with conn() as db:
        batch = db.execute(
            """SELECT mb.*,ub.workflow_mode
               FROM migration_batches mb
               JOIN upload_batches ub ON ub.id=mb.upload_batch_id
               WHERE mb.id=?""",
            (migration_batch_id,),
        ).fetchone()
        rows = db.execute(
            """SELECT u.*
               FROM migration_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.migration_batch_id=?
               ORDER BY u.id""",
            (migration_batch_id,),
        ).fetchall()

    if not batch:
        return {"ready": False, "reason": "Migration batch not found"}
    if not rows:
        return {"ready": False, "reason": "Migration batch has no users"}

    if batch["workflow_mode"] not in ("existing_password", "existing_password_retry"):
        not_m365_ready = [
            int(row["id"]) for row in rows
            if row.get("provisioning_status") != "m365_ready"
        ]
        if not_m365_ready:
            return {
                "ready": False,
                "reason": f"{len(not_m365_ready)} selected user(s) are not yet Microsoft 365 mailbox-ready",
                "not_m365_ready": not_m365_ready,
            }

    if batch["workflow_mode"] == "manual_bulk":
        unconfirmed = [
            int(row["id"]) for row in rows
            if row["rackspace_status"] != "manual_confirmed"
        ]
        if unconfirmed:
            return {
                "ready": False,
                "reason": f"{len(unconfirmed)} selected user(s) have not yet been confirmed as updated in Rackspace",
                "unconfirmed": unconfirmed,
            }

    object_ids: list[int] = []
    failed: list[dict] = []
    for row in rows:
        user = dict(row)
        try:
            if batch["workflow_mode"] == "manual_bulk":
                oid = await prepare_manual_user(int(user["id"]))
            elif batch["workflow_mode"] in ("existing_password", "existing_password_retry"):
                oid = await prepare_existing_password_user(int(user["id"]))
            else:
                oid = await prepare_user(int(user["id"]))
            object_ids.append(int(oid))
        except Exception as exc:
            failed.append({"user_id": int(user["id"]), "error": str(exc)})
            with conn() as db:
                db.execute(
                    """UPDATE users SET migration_status='failed',error_message=?,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (str(exc)[:3000], int(user["id"])),
                )

    if failed:
        with conn() as db:
            db.execute(
                """UPDATE migration_batches
                   SET workflow_status='attention',last_error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (f"{len(failed)} user(s) failed Cloudiway preparation", migration_batch_id),
            )
        return {
            "ready": False,
            "reason": f"{len(failed)} user(s) failed Cloudiway preparation",
            "failed": failed,
        }

    cloud_batch_id = await assign_migration_batch_members(migration_batch_id, object_ids)
    with conn() as db:
        db.execute(
            """UPDATE migration_batches
               SET workflow_status='ready_to_migrate',last_error=NULL,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (migration_batch_id,),
        )
    return {
        "ready": True,
        "migration_batch_id": migration_batch_id,
        "cloudiway_batch_id": cloud_batch_id,
        "users": len(rows),
        "object_ids": object_ids,
    }


async def start_migration_batch(migration_batch_id: int) -> dict:
    """Start one selected batch, restarting existing errored Cloudiway objects in place."""
    with conn() as db:
        batch = db.execute(
            "SELECT * FROM migration_batches WHERE id=?",
            (migration_batch_id,),
        ).fetchone()
        rows = db.execute(
            """SELECT u.id,u.cloudiway_object_id,u.cloudiway_status,u.migration_status
               FROM migration_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.migration_batch_id=?
               ORDER BY u.id""",
            (migration_batch_id,),
        ).fetchall()

    if not batch:
        return {"started": False, "reason": "Migration batch not found"}

    object_ids = [int(r["cloudiway_object_id"]) for r in rows if r.get("cloudiway_object_id")]
    already_prepared = (
        batch["workflow_status"] == "ready_to_migrate"
        and len(object_ids) == len(rows)
        and len(rows) > 0
    )

    if not already_prepared:
        prepared = await prepare_migration_batch(migration_batch_id)
        if not prepared.get("ready"):
            return {"started": False, **prepared}

    # Re-read because preparation may have classified existing Cloudiway objects
    # as restart_required / already migrating / already completed.
    with conn() as db:
        rows = db.execute(
            """SELECT u.id,u.cloudiway_object_id,u.cloudiway_status,u.migration_status
               FROM migration_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.migration_batch_id=?
               ORDER BY u.id""",
            (migration_batch_id,),
        ).fetchall()

    cloud = await _cloudiway_client_ready()
    start_ids: list[int] = []
    restart_rows: list[tuple[int, int]] = []
    running_user_ids: list[int] = []
    completed_user_ids: list[int] = []

    for row in rows:
        uid = int(row["id"])
        oid = row.get("cloudiway_object_id")
        if not oid:
            continue
        oid = int(oid)
        state = str(row.get("cloudiway_status") or "")
        if state == "restart_required":
            restart_rows.append((uid, oid))
        elif state == "existing_migrating":
            running_user_ids.append(uid)
        elif state == "existing_completed":
            completed_user_ids.append(uid)
        else:
            start_ids.append(oid)

    if start_ids:
        await cloud.start_migration(start_ids)

    restarted_user_ids: list[int] = []
    for uid, oid in restart_rows:
        await cloud.restart_migration(oid)
        restarted_user_ids.append(uid)
        log_event(
            uid,
            "cloudiway_existing_migration_restarted",
            f"Reused Cloudiway object {oid}; refreshed source password and restarted existing migration.",
        )

    active_user_ids = [
        int(r["id"])
        for r in rows
        if int(r["id"]) not in completed_user_ids
    ]
    if active_user_ids:
        placeholders = ",".join("?" for _ in active_user_ids)
        with conn() as db:
            db.execute(
                f"""UPDATE users
                    SET migration_status='migrating',batch_number=?,
                        batch_started_at=COALESCE(batch_started_at,CURRENT_TIMESTAMP),
                        error_message=NULL,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id IN ({placeholders})""",
                (migration_batch_id, *active_user_ids),
            )
    if completed_user_ids:
        placeholders = ",".join("?" for _ in completed_user_ids)
        with conn() as db:
            db.execute(
                f"""UPDATE users SET migration_status='completed',
                    error_message=NULL,updated_at=CURRENT_TIMESTAMP
                    WHERE id IN ({placeholders})""",
                tuple(completed_user_ids),
            )

    with conn() as db:
        db.execute(
            """UPDATE migration_batches
               SET workflow_status=?,last_error=NULL,updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                "completed" if len(completed_user_ids) == len(rows) and rows else "migrating",
                migration_batch_id,
            ),
        )

    set_runtime("automation_running", "1")
    log_event(
        None,
        "migration_batch_started",
        f"Migration batch {migration_batch_id}: new starts={len(start_ids)}, "
        f"existing restarts={len(restarted_user_ids)}, already running={len(running_user_ids)}, "
        f"already completed={len(completed_user_ids)}",
    )
    return {
        "started": bool(start_ids or restarted_user_ids or running_user_ids),
        "migration_batch_id": migration_batch_id,
        "cloudiway_batch_id": int(batch["cloudiway_batch_id"]) if batch.get("cloudiway_batch_id") else None,
        "users_started": len(start_ids),
        "users_restarted": len(restarted_user_ids),
        "users_already_running": len(running_user_ids),
        "users_already_completed": len(completed_user_ids),
    }


async def prepare_manual_upload_batch(upload_batch_id: int) -> dict:
    """Prepare every confirmed member of an upload batch and assign it to its Cloudiway batch."""
    with conn() as db:
        rows = db.execute(
            """SELECT u.*
               FROM upload_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.upload_batch_id=?
               ORDER BY u.id""",
            (upload_batch_id,),
        ).fetchall()

    if not rows:
        return {"ready": False, "reason": "This upload batch has no users"}

    unconfirmed = [
        int(row["id"])
        for row in rows
        if row["password_reset_method"] == "manual_bulk"
        and row["rackspace_status"] != "manual_confirmed"
    ]
    if unconfirmed:
        return {
            "ready": False,
            "reason": f"{len(unconfirmed)} user(s) have not yet been confirmed as updated in Rackspace",
            "unconfirmed": unconfirmed,
        }

    object_ids: list[int] = []
    prepared_ids: list[int] = []
    failed: list[dict] = []
    for row in rows:
        user = dict(row)
        try:
            if user["password_reset_method"] == "manual_bulk":
                oid = await prepare_manual_user(int(user["id"]))
            elif user["password_reset_method"] == "existing_password":
                oid = await prepare_existing_password_user(int(user["id"]))
            else:
                oid = await prepare_user(int(user["id"]))
            object_ids.append(int(oid))
            prepared_ids.append(int(user["id"]))
        except Exception as exc:
            failed.append({"user_id": int(user["id"]), "error": str(exc)})

    if failed:
        with conn() as db:
            db.execute(
                """UPDATE upload_batches
                   SET workflow_status='attention',last_error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (f"{len(failed)} user(s) failed Cloudiway preparation"[:3000], upload_batch_id),
            )
        return {
            "ready": False,
            "reason": f"{len(failed)} user(s) failed Cloudiway preparation",
            "failed": failed,
        }

    cloud_batch_id = await assign_upload_batch_members(upload_batch_id, object_ids)
    with conn() as db:
        db.execute(
            """UPDATE upload_batches
               SET workflow_status='ready_to_migrate',last_error=NULL,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (upload_batch_id,),
        )
    return {
        "ready": True,
        "upload_batch_id": upload_batch_id,
        "cloudiway_batch_id": cloud_batch_id,
        "users": len(prepared_ids),
        "object_ids": object_ids,
    }


async def start_upload_batch(upload_batch_id: int) -> dict:
    """Prepare, Cloudiway-batch, and start an entire upload as one workflow unit."""
    prepared = await prepare_manual_upload_batch(upload_batch_id)
    if not prepared.get("ready"):
        return {"started": False, **prepared}

    object_ids = prepared["object_ids"]
    with conn() as db:
        member_rows = db.execute(
            "SELECT user_id FROM upload_batch_members WHERE upload_batch_id=?",
            (upload_batch_id,),
        ).fetchall()
    user_ids = [int(r["user_id"]) for r in member_rows]

    cloud = await _cloudiway_client_ready()
    await cloud.start_migration(object_ids)

    if user_ids:
        placeholders = ",".join("?" for _ in user_ids)
        with conn() as db:
            db.execute(
                f"""UPDATE users
                    SET migration_status='migrating',batch_number=?,
                        batch_started_at=CURRENT_TIMESTAMP,error_message=NULL,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id IN ({placeholders})""",
                (upload_batch_id, *user_ids),
            )
            db.execute(
                """UPDATE upload_batches
                   SET workflow_status='migrating',last_error=NULL,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (upload_batch_id,),
            )

    set_runtime("automation_running", "1")
    log_event(
        None,
        "upload_batch_started",
        f"Upload batch {upload_batch_id} started in Cloudiway batch {prepared['cloudiway_batch_id']} with {len(user_ids)} user(s)",
    )
    return {
        "started": True,
        "upload_batch_id": upload_batch_id,
        "cloudiway_batch_id": prepared["cloudiway_batch_id"],
        "users_started": len(user_ids),
    }


async def advance_upload_workflows() -> dict:
    """Background maintenance for incremental migration batches."""
    summary = {"cloudiway_batches_created": 0, "auto_started": 0, "errors": 0}

    if not get_setting("cloudiway_token"):
        return summary

    with conn() as db:
        pending = db.execute(
            """SELECT id FROM migration_batches
               WHERE cloudiway_batch_id IS NULL
                 AND workflow_status NOT IN ('completed')
               ORDER BY id LIMIT 20"""
        ).fetchall()

    for row in pending:
        try:
            await ensure_migration_cloudiway_batch(int(row["id"]))
            summary["cloudiway_batches_created"] += 1
        except Exception:
            summary["errors"] += 1

    with conn() as db:
        auto_rows = db.execute(
            """SELECT id FROM migration_batches
               WHERE auto_start=1
                 AND workflow_status IN ('passwords_confirmed','ready_to_migrate','ready_for_automatic')
               ORDER BY id LIMIT 5"""
        ).fetchall()

    for row in auto_rows:
        try:
            result = await start_migration_batch(int(row["id"]))
            if result.get("started"):
                summary["auto_started"] += 1
        except Exception as exc:
            summary["errors"] += 1
            with conn() as db:
                db.execute(
                    """UPDATE migration_batches SET workflow_status='attention',last_error=?,
                       updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (str(exc)[:3000], int(row["id"])),
                )

    return summary


def refresh_upload_batch_states() -> None:
    """Roll up user states into incremental batches and their parent uploads."""
    with conn() as db:
        migration_batches = db.execute(
            """SELECT mb.id,mb.workflow_status,
                      COUNT(m.user_id) total,
                      SUM(u.migration_status='completed') completed,
                      SUM(u.migration_status IN ('failed','attention','timed_out')) problems,
                      SUM(u.migration_status='migrating') migrating
               FROM migration_batches mb
               LEFT JOIN migration_batch_members m ON m.migration_batch_id=mb.id
               LEFT JOIN users u ON u.id=m.user_id
               GROUP BY mb.id,mb.workflow_status"""
        ).fetchall()

        for row in migration_batches:
            total = int(row["total"] or 0)
            completed = int(row["completed"] or 0)
            problems = int(row["problems"] or 0)
            migrating = int(row["migrating"] or 0)
            new_status = None
            if total and completed == total:
                new_status = "completed"
            elif problems:
                new_status = "attention"
            elif migrating:
                new_status = "migrating"
            if new_status and new_status != row["workflow_status"]:
                db.execute(
                    "UPDATE migration_batches SET workflow_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (new_status, int(row["id"])),
                )

        uploads = db.execute(
            """SELECT ub.id,ub.workflow_status,
                      COUNT(ubm.user_id) total,
                      SUM(mbm.user_id IS NOT NULL) assigned,
                      SUM(u.migration_status='completed') completed,
                      SUM(u.migration_status IN ('failed','attention','timed_out')) problems,
                      SUM(u.migration_status='migrating') migrating
               FROM upload_batches ub
               LEFT JOIN upload_batch_members ubm ON ubm.upload_batch_id=ub.id
               LEFT JOIN users u ON u.id=ubm.user_id
               LEFT JOIN migration_batch_members mbm ON mbm.user_id=u.id
               GROUP BY ub.id,ub.workflow_status"""
        ).fetchall()

        for row in uploads:
            total = int(row["total"] or 0)
            assigned = int(row["assigned"] or 0)
            completed = int(row["completed"] or 0)
            problems = int(row["problems"] or 0)
            migrating = int(row["migrating"] or 0)
            if total and completed == total:
                state = "completed"
            elif problems:
                state = "attention"
            elif migrating:
                state = "migrating"
            elif assigned and assigned == total:
                state = "fully_batched"
            elif assigned:
                state = "partially_batched"
            else:
                state = "staged"
            if state != row["workflow_status"]:
                db.execute(
                    "UPDATE upload_batches SET workflow_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (state, int(row["id"])),
                )


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
