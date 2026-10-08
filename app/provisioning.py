import json
from datetime import datetime, timezone

from app.clients.active_directory import ActiveDirectoryClient
from app.clients.microsoft_graph import MicrosoftGraphClient
from app.clients.sql_source import SqlSourceClient
from app.clients.sync_agent import SyncAgentClient
from app.db import conn, log_event
from app.security import decrypt_secret


def _rowdict(row):
    return dict(row) if row else None


def list_profiles() -> list[dict]:
    with conn() as db:
        return [
            dict(r)
            for r in db.execute(
                """SELECT id,name,environment_type,is_active,writes_enabled,emergency_stop,
                          production_max_batch,ad_host,ad_port,ad_use_ssl,ad_base_dn,
                          ad_bind_username,ad_target_ou,ad_license_group_dn,
                          ad_computer_number_attribute,ad_upn_suffix,
                          ad_force_password_change,ad_allow_user_creation,ad_allow_group_changes,
                          graph_tenant_id,graph_client_id,graph_required_sku,
                          sync_agent_url,sql_host,sql_port,sql_database,sql_username,
                          sql_source_view,vpn_profile_name,network_notes,created_at,updated_at
                   FROM environment_profiles ORDER BY is_active DESC,name"""
            ).fetchall()
        ]


def get_profile(profile_id: int) -> dict | None:
    with conn() as db:
        return _rowdict(
            db.execute("SELECT * FROM environment_profiles WHERE id=?", (profile_id,)).fetchone()
        )


def get_active_profile() -> dict | None:
    with conn() as db:
        return _rowdict(
            db.execute(
                "SELECT * FROM environment_profiles WHERE is_active=1 ORDER BY id LIMIT 1"
            ).fetchone()
        )


def _secret(profile: dict, key: str) -> str:
    return decrypt_secret(profile.get(key)) or ""


def ad_client_for_profile(profile: dict) -> ActiveDirectoryClient:
    return ActiveDirectoryClient(
        host=profile.get("ad_host") or "",
        port=int(profile.get("ad_port") or 636),
        use_ssl=bool(profile.get("ad_use_ssl", 1)),
        bind_username=profile.get("ad_bind_username") or "",
        bind_password=_secret(profile, "ad_bind_password_enc"),
        base_dn=profile.get("ad_base_dn") or "",
        target_ou=profile.get("ad_target_ou") or "",
        license_group_dn=profile.get("ad_license_group_dn") or "",
        computer_number_attribute=profile.get("ad_computer_number_attribute") or "",
        upn_suffix=profile.get("ad_upn_suffix") or "",
    )


def graph_client_for_profile(profile: dict) -> MicrosoftGraphClient:
    return MicrosoftGraphClient(
        tenant_id=profile.get("graph_tenant_id") or "",
        client_id=profile.get("graph_client_id") or "",
        client_secret=_secret(profile, "graph_client_secret_enc"),
        required_sku=profile.get("graph_required_sku") or "",
    )


def sql_client_for_profile(profile: dict) -> SqlSourceClient:
    return SqlSourceClient(
        host=profile.get("sql_host") or "",
        port=int(profile.get("sql_port") or 1433),
        database=profile.get("sql_database") or "",
        username=profile.get("sql_username") or "",
        password=_secret(profile, "sql_password_enc"),
    )


def sync_client_for_profile(profile: dict) -> SyncAgentClient | None:
    url = (profile.get("sync_agent_url") or "").strip()
    if not url:
        return None
    return SyncAgentClient(url, _secret(profile, "sync_agent_token_enc"))


def validate_profile_configuration(profile: dict) -> list[str]:
    missing = []
    required = {
        "AD host": profile.get("ad_host"),
        "AD base DN": profile.get("ad_base_dn"),
        "AD bind username": profile.get("ad_bind_username"),
        "AD bind password": profile.get("ad_bind_password_enc"),
        "AD target OU": profile.get("ad_target_ou"),
        "AD licensing group": profile.get("ad_license_group_dn"),
        "AD Computer Number attribute": profile.get("ad_computer_number_attribute"),
        "Microsoft tenant ID": profile.get("graph_tenant_id"),
        "Microsoft Graph client ID": profile.get("graph_client_id"),
        "Microsoft Graph client secret": profile.get("graph_client_secret_enc"),
    }
    for label, value in required.items():
        if not value:
            missing.append(label)
    return missing


def _assert_writes_allowed(profile: dict, selected_count: int = 1) -> None:
    if int(profile.get("emergency_stop") or 0) == 1:
        raise RuntimeError("Emergency Stop is active. All directory write operations are blocked.")
    if int(profile.get("writes_enabled") or 0) != 1:
        raise RuntimeError("Directory writes are disabled for the active environment profile.")
    if str(profile.get("environment_type") or "").upper() == "PRODUCTION":
        maximum = int(profile.get("production_max_batch") or 100)
        if selected_count > maximum:
            raise RuntimeError(
                f"Production provisioning batch size {selected_count} exceeds the configured maximum of {maximum}."
            )


def _load_user(user_id: int) -> dict:
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise RuntimeError("User not found")
    return dict(row)


def assess_user(user_id: int, profile_id: int | None = None) -> dict:
    user = _load_user(user_id)
    profile = get_profile(profile_id) if profile_id else get_active_profile()
    if not profile:
        raise RuntimeError("No Active Directory environment profile is active")
    missing = validate_profile_configuration(profile)
    if missing:
        raise RuntimeError("Provisioning profile is incomplete: " + ", ".join(missing))

    if not user.get("computer_number"):
        decision = {
            "status": "manual_review",
            "reason": "Computer Number is missing from the uploaded record.",
            "candidates": [],
        }
    elif not user.get("first_name") or not user.get("last_name"):
        decision = {
            "status": "manual_review",
            "reason": "First name and last name are required for AD identity confirmation.",
            "candidates": [],
        }
    else:
        client = ad_client_for_profile(profile)
        decision = client.identity_decision(
            target_email=user.get("target_email") or "",
            source_email=user.get("source_email") or "",
            computer_number=user.get("computer_number") or "",
            first_name=user.get("first_name") or "",
            last_name=user.get("last_name") or "",
        )

    selected = decision.get("selected") or {}
    status = decision["status"]
    if status == "confirmed":
        provisioning = "ad_confirmed"
        ad_enabled = "enabled" if selected.get("enabled") else "disabled"
    elif status == "not_found":
        provisioning = "ad_create_pending"
        ad_enabled = "not_applicable"
    else:
        provisioning = "manual_review"
        ad_enabled = "enabled" if selected.get("enabled") else ("disabled" if selected else None)

    with conn() as db:
        db.execute(
            """UPDATE users
               SET provisioning_profile_id=?,provisioning_status=?,ad_match_status=?,
                   ad_object_guid=?,ad_distinguished_name=?,ad_candidate_json=?,
                   ad_conflict_reason=?,ad_enabled_status=?,ad_manual_override=0,
                   ad_resolution_note=NULL,ad_resolved_at=NULL,provisioning_error=NULL,
                   provisioning_updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                int(profile["id"]),
                provisioning,
                status,
                selected.get("object_guid") or None,
                selected.get("dn") or None,
                json.dumps(decision.get("candidates") or [], default=str),
                None if status == "confirmed" else decision.get("reason"),
                ad_enabled,
                user_id,
            ),
        )
    log_event(user_id, "ad_identity_assessed", f"{status}: {decision.get('reason','')}")
    return decision


def assess_migration_batch(migration_batch_id: int) -> dict:
    profile = get_active_profile()
    if not profile:
        raise RuntimeError("No environment profile is active")
    with conn() as db:
        batch = db.execute(
            "SELECT * FROM migration_batches WHERE id=?", (migration_batch_id,)
        ).fetchone()
        rows = db.execute(
            """SELECT u.id
               FROM migration_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.migration_batch_id=?
               ORDER BY u.id""",
            (migration_batch_id,),
        ).fetchall()
    if not batch:
        raise RuntimeError("Migration batch not found")
    if not rows:
        raise RuntimeError("Migration batch has no users")

    if str(profile.get("environment_type") or "").upper() == "PRODUCTION":
        maximum = int(profile.get("production_max_batch") or 100)
        if len(rows) > maximum:
            raise RuntimeError(
                f"Selected batch contains {len(rows)} users; production maximum is {maximum}."
            )

    summary = {"confirmed": 0, "not_found": 0, "manual_review": 0, "errors": 0}
    for row in rows:
        try:
            decision = assess_user(int(row["id"]), int(profile["id"]))
            key = decision.get("status")
            if key in summary:
                summary[key] += 1
        except Exception as exc:
            summary["errors"] += 1
            with conn() as db:
                db.execute(
                    """UPDATE users SET provisioning_profile_id=?,provisioning_status='assessment_error',
                       provisioning_error=?,provisioning_updated_at=CURRENT_TIMESTAMP
                       WHERE id=?""",
                    (int(profile["id"]), str(exc)[:3000], int(row["id"])),
                )
            log_event(int(row["id"]), "ad_identity_assessment_failed", str(exc))

    state = "provisioning_review" if summary["manual_review"] or summary["errors"] else "provisioning_assessed"
    with conn() as db:
        db.execute(
            """UPDATE migration_batches
               SET provisioning_profile_id=?,workflow_status=?,last_error=?,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (
                int(profile["id"]),
                state,
                (
                    f"{summary['manual_review']} manual review; {summary['errors']} assessment errors"
                    if state == "provisioning_review"
                    else None
                ),
                migration_batch_id,
            ),
        )
    log_event(None, "provisioning_batch_assessed", f"Batch {migration_batch_id}: {summary}")
    return {"profile": profile["name"], **summary}


def _candidate_from_saved(user: dict, candidate_dn: str) -> dict | None:
    try:
        candidates = json.loads(user.get("ad_candidate_json") or "[]")
    except Exception:
        candidates = []
    for candidate in candidates:
        if str(candidate.get("dn") or "").lower() == candidate_dn.strip().lower():
            return candidate
    return None


def resolve_manual_review(user_id: int, candidate_dn: str, note: str) -> dict:
    if not note.strip():
        raise RuntimeError("A resolution note is required")
    user = _load_user(user_id)
    if user.get("ad_match_status") != "manual_review":
        raise RuntimeError("This user is not currently waiting for manual AD review")
    candidate = _candidate_from_saved(user, candidate_dn)
    if not candidate:
        raise RuntimeError("The selected AD object is not one of the reviewed candidates")
    if not candidate.get("enabled"):
        raise RuntimeError(
            "The selected AD account is still disabled. Correct it in AD and use Re-check before continuing."
        )
    with conn() as db:
        db.execute(
            """UPDATE users
               SET ad_match_status='manual_resolved',ad_manual_override=1,
                   ad_object_guid=?,ad_distinguished_name=?,ad_enabled_status='enabled',
                   ad_conflict_reason=NULL,ad_resolution_note=?,ad_resolved_at=CURRENT_TIMESTAMP,
                   provisioning_status='ad_confirmed',provisioning_error=NULL,
                   provisioning_updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                candidate.get("object_guid") or None,
                candidate.get("dn") or None,
                note.strip()[:2000],
                user_id,
            ),
        )
    log_event(
        user_id,
        "ad_manual_review_resolved",
        f"Administrator selected AD object {candidate.get('dn')} and continued. Note: {note.strip()[:500]}",
    )
    return candidate


def provision_user(user_id: int) -> dict:
    user = _load_user(user_id)
    profile = get_profile(int(user["provisioning_profile_id"])) if user.get("provisioning_profile_id") else get_active_profile()
    if not profile:
        raise RuntimeError("No provisioning profile is available")
    _assert_writes_allowed(profile, 1)
    client = ad_client_for_profile(profile)

    status = user.get("ad_match_status")
    if status in ("confirmed", "manual_resolved", "created"):
        if user.get("ad_enabled_status") != "enabled":
            raise RuntimeError("Existing AD account is not enabled; manual correction is required")
        user_dn = user.get("ad_distinguished_name")
        if not user_dn:
            raise RuntimeError("Confirmed AD account has no distinguished name")
        if not client.is_group_member(user_dn):
            if int(profile.get("ad_allow_group_changes") or 0) != 1:
                raise RuntimeError("User is not in the licensing group and automatic group changes are disabled")
            client.add_to_license_group(user_dn)
        created = False
        object_guid = user.get("ad_object_guid")
    elif status == "not_found":
        if int(profile.get("ad_allow_user_creation") or 0) != 1:
            raise RuntimeError("AD account is missing and automatic user creation is disabled")
        temporary_password = _secret(profile, "ad_default_password_enc")
        if not temporary_password:
            raise RuntimeError("No temporary AD password is configured")
        result = client.create_user(
            target_email=user.get("target_email") or "",
            first_name=user.get("first_name") or "",
            middle_name=user.get("middle_name") or "",
            last_name=user.get("last_name") or "",
            computer_number=user.get("computer_number") or "",
            temporary_password=temporary_password,
            force_change_at_logon=bool(profile.get("ad_force_password_change", 1)),
        )
        user_dn = result.get("dn")
        object_guid = result.get("object_guid")
        created = True
    else:
        raise RuntimeError("User has not passed AD identity review")

    with conn() as db:
        db.execute(
            """UPDATE users
               SET ad_created_by_app=?,ad_match_status=?,
                   ad_enabled_status='enabled',ad_distinguished_name=?,ad_object_guid=?,
                   ad_group_status='member',provisioning_status='sync_pending',
                   entra_status='pending',license_status='pending',mailbox_status='pending',
                   provisioning_error=NULL,provisioning_updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                1 if created else int(user.get("ad_created_by_app") or 0),
                "created" if created else status,
                user_dn,
                object_guid,
                user_id,
            ),
        )
    log_event(
        user_id,
        "ad_provisioned",
        "Created and provisioned new AD account" if created else "Existing AD account validated and licensing group membership ensured",
    )
    return {"ok": True, "created": created, "dn": user_dn, "object_guid": object_guid}


async def provision_migration_batch(migration_batch_id: int) -> dict:
    with conn() as db:
        batch = db.execute(
            "SELECT * FROM migration_batches WHERE id=?", (migration_batch_id,)
        ).fetchone()
        rows = db.execute(
            """SELECT u.id,u.provisioning_status,u.ad_match_status
               FROM migration_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.migration_batch_id=? ORDER BY u.id""",
            (migration_batch_id,),
        ).fetchall()
    if not batch:
        raise RuntimeError("Migration batch not found")
    profile = get_profile(int(batch["provisioning_profile_id"])) if batch.get("provisioning_profile_id") else get_active_profile()
    if not profile:
        raise RuntimeError("No provisioning profile is active")
    _assert_writes_allowed(profile, len(rows))

    result = {"provisioned": 0, "manual_review": 0, "failed": 0}
    for row in rows:
        if row["ad_match_status"] == "manual_review":
            result["manual_review"] += 1
            continue
        try:
            provision_user(int(row["id"]))
            result["provisioned"] += 1
        except Exception as exc:
            result["failed"] += 1
            with conn() as db:
                db.execute(
                    """UPDATE users SET provisioning_status='provisioning_error',
                       provisioning_error=?,provisioning_updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (str(exc)[:3000], int(row["id"])),
                )
            log_event(int(row["id"]), "ad_provisioning_failed", str(exc))

    if result["failed"]:
        batch_state = "provisioning_attention"
    elif result["manual_review"]:
        batch_state = "provisioning_review"
    else:
        batch_state = "sync_pending"

    sync_note = ""
    if result["provisioned"] and result["manual_review"] == 0 and result["failed"] == 0:
        sync = sync_client_for_profile(profile)
        if sync:
            try:
                response = await sync.trigger_delta_sync()
                sync_note = "Delta synchronization requested."
                log_event(None, "entra_delta_sync_requested", f"Batch {migration_batch_id}: {response}")
            except Exception as exc:
                sync_note = "Sync-agent request failed; normal Entra Connect schedule may still synchronize users."
                log_event(None, "entra_delta_sync_failed", f"Batch {migration_batch_id}: {exc}")
        else:
            sync_note = "No sync agent configured; waiting for normal Entra Connect synchronization."

        with conn() as db:
            db.execute(
                """UPDATE migration_batches SET sync_requested_at=CURRENT_TIMESTAMP,
                   workflow_status='sync_pending',last_error=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (migration_batch_id,),
            )
    else:
        with conn() as db:
            db.execute(
                """UPDATE migration_batches SET workflow_status=?,last_error=?,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (
                    batch_state,
                    (
                        f"{result['manual_review']} user(s) require manual review; "
                        f"{result['failed']} provisioning failure(s)"
                    ),
                    migration_batch_id,
                ),
            )

    return {**result, "sync_note": sync_note, "workflow_status": batch_state if not sync_note else "sync_pending"}


async def refresh_m365_user(user_id: int) -> dict:
    user = _load_user(user_id)
    profile = get_profile(int(user["provisioning_profile_id"])) if user.get("provisioning_profile_id") else get_active_profile()
    if not profile:
        raise RuntimeError("No provisioning profile is available")
    graph = graph_client_for_profile(profile)

    target = user.get("target_email") or ""
    remote = await graph.get_user(target)
    if not remote:
        with conn() as db:
            db.execute(
                """UPDATE users SET entra_status='pending',license_status='pending',
                   mailbox_status='pending',provisioning_status='sync_pending',
                   provisioning_updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (user_id,),
            )
        return {"entra": "pending", "license": "pending", "mailbox": "pending"}

    if remote.get("accountEnabled") is False:
        with conn() as db:
            db.execute(
                """UPDATE users SET entra_status='disabled',provisioning_status='manual_review',
                   provisioning_error='Synced Microsoft Entra account is disabled',
                   provisioning_updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (user_id,),
            )
        return {"entra": "disabled", "license": "not_checked", "mailbox": "not_checked"}

    object_id = remote.get("id")
    license_ok, sku_names = await graph.license_ready(object_id)
    if not license_ok:
        with conn() as db:
            db.execute(
                """UPDATE users SET entra_status='synced',entra_object_id=?,license_status='pending',
                   mailbox_status='pending',provisioning_status='license_pending',
                   provisioning_error=NULL,provisioning_updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (object_id, user_id),
            )
        return {"entra": "synced", "license": "pending", "skus": sku_names, "mailbox": "pending"}

    mailbox_ok, mailbox_detail = await graph.mailbox_ready(object_id)
    final_status = "m365_ready" if mailbox_ok else "mailbox_pending"
    with conn() as db:
        db.execute(
            """UPDATE users SET entra_status='synced',entra_object_id=?,license_status='licensed',
               mailbox_status=?,provisioning_status=?,provisioning_error=NULL,
               provisioning_updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (
                object_id,
                "ready" if mailbox_ok else "pending",
                final_status,
                user_id,
            ),
        )
    if mailbox_ok:
        log_event(user_id, "m365_mailbox_ready", "Microsoft 365 licence and Exchange mailbox are ready")
    return {
        "entra": "synced",
        "license": "licensed",
        "skus": sku_names,
        "mailbox": "ready" if mailbox_ok else "pending",
        "mailbox_detail": mailbox_detail,
    }


async def refresh_migration_batch_readiness(migration_batch_id: int) -> dict:
    with conn() as db:
        batch = db.execute(
            "SELECT * FROM migration_batches WHERE id=?", (migration_batch_id,)
        ).fetchone()
        rows = db.execute(
            """SELECT u.id,u.provisioning_status
               FROM migration_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.migration_batch_id=? ORDER BY u.id""",
            (migration_batch_id,),
        ).fetchall()
    if not batch:
        raise RuntimeError("Migration batch not found")

    checked = ready = pending = failed = 0
    for row in rows:
        if row["provisioning_status"] in ("manual_review", "assessment_error", "provisioning_error"):
            failed += 1
            continue
        if row["provisioning_status"] == "m365_ready":
            ready += 1
            continue
        try:
            result = await refresh_m365_user(int(row["id"]))
            checked += 1
            if result.get("mailbox") == "ready":
                ready += 1
            else:
                pending += 1
        except Exception as exc:
            pending += 1
            log_event(int(row["id"]), "m365_readiness_check_failed", str(exc))

    total = len(rows)
    if total and ready == total:
        state = "m365_ready"
        with conn() as db:
            db.execute(
                """UPDATE migration_batches SET workflow_status='m365_ready',
                   m365_ready_at=COALESCE(m365_ready_at,CURRENT_TIMESTAMP),
                   last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (migration_batch_id,),
            )
        log_event(None, "migration_batch_m365_ready", f"Batch {migration_batch_id}: all {total} users ready")
    elif failed:
        state = "provisioning_review"
        with conn() as db:
            db.execute(
                """UPDATE migration_batches SET workflow_status='provisioning_review',
                   last_error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (f"{failed} user(s) require provisioning review", migration_batch_id),
            )
    else:
        state = "m365_waiting"
        with conn() as db:
            db.execute(
                """UPDATE migration_batches SET workflow_status='m365_waiting',
                   last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (migration_batch_id,),
            )

    return {"total": total, "ready": ready, "pending": pending, "failed": failed, "checked": checked, "state": state}


async def refresh_pending_provisioning_batches(limit: int = 10) -> dict:
    with conn() as db:
        rows = db.execute(
            """SELECT id FROM migration_batches
               WHERE workflow_status IN ('sync_pending','m365_waiting','license_pending','mailbox_pending')
               ORDER BY id LIMIT ?""",
            (limit,),
        ).fetchall()
    summary = {"checked": 0, "ready": 0, "errors": 0}
    for row in rows:
        try:
            result = await refresh_migration_batch_readiness(int(row["id"]))
            summary["checked"] += 1
            if result.get("state") == "m365_ready":
                summary["ready"] += 1
        except Exception as exc:
            summary["errors"] += 1
            log_event(None, "provisioning_background_check_failed", f"Batch {row['id']}: {exc}")
    return summary
