import re
import uuid
from typing import Any

from ldap3 import ALL, BASE, SUBTREE, Connection, MODIFY_ADD, MODIFY_REPLACE, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn


_ATTRIBUTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


def _normalize_text(value: str | None) -> str:
    return " ".join((value or "").strip().lower().split())


def _guid_to_text(value: Any) -> str:
    if isinstance(value, bytes) and len(value) == 16:
        return str(uuid.UUID(bytes_le=value))
    if value is None:
        return ""
    return str(value)


class ActiveDirectoryClient:
    """Restricted AD client intended for LDAPS and delegated OU/group permissions."""

    def __init__(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        bind_username: str,
        bind_password: str,
        base_dn: str,
        target_ou: str,
        license_group_dn: str,
        computer_number_attribute: str,
        upn_suffix: str = "",
    ):
        self.host = host
        self.port = int(port or 636)
        self.use_ssl = bool(use_ssl)
        self.bind_username = bind_username
        self.bind_password = bind_password
        self.base_dn = base_dn
        self.target_ou = target_ou
        self.license_group_dn = license_group_dn
        self.computer_number_attribute = computer_number_attribute
        self.upn_suffix = upn_suffix

        if not _ATTRIBUTE_RE.fullmatch(computer_number_attribute or ""):
            raise RuntimeError("Invalid AD computer-number attribute name")
        if not self.target_ou or not self.base_dn:
            raise RuntimeError("AD base DN and target OU are required")
        if not _normalize_text(self.target_ou).endswith(_normalize_text(self.base_dn)):
            raise RuntimeError("Configured target OU is outside the configured AD base DN")

    def _connect(self) -> Connection:
        server = Server(
            self.host,
            port=self.port,
            use_ssl=self.use_ssl,
            get_info=ALL,
            connect_timeout=10,
        )
        conn = Connection(
            server,
            user=self.bind_username,
            password=self.bind_password,
            auto_bind=True,
            receive_timeout=20,
        )
        return conn

    def test_connection(self) -> dict:
        conn = self._connect()
        try:
            ok = conn.search(
                self.base_dn,
                "(objectClass=domainDNS)",
                search_scope=BASE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            if not ok and conn.result.get("result") not in (0,):
                raise RuntimeError(conn.result.get("message") or "AD base DN query failed")

            ou_ok = conn.search(
                self.target_ou,
                "(objectClass=organizationalUnit)",
                search_scope=BASE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            if not ou_ok or not conn.entries:
                raise RuntimeError("Configured provisioning OU was not found")

            group_ok = conn.search(
                self.license_group_dn,
                "(objectClass=group)",
                search_scope=BASE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            if not group_ok or not conn.entries:
                raise RuntimeError("Configured Microsoft 365 licensing AD group was not found")

            return {
                "ok": True,
                "host": self.host,
                "base_dn": self.base_dn,
                "target_ou": self.target_ou,
                "license_group_dn": self.license_group_dn,
                "computer_number_attribute": self.computer_number_attribute,
            }
        finally:
            conn.unbind()

    def _entry_to_dict(self, entry) -> dict:
        attrs = entry.entry_attributes_as_dict
        def first(name):
            value = attrs.get(name)
            if isinstance(value, list):
                return value[0] if value else ""
            return value or ""

        uac_raw = first("userAccountControl")
        try:
            uac = int(uac_raw)
        except Exception:
            uac = 0

        proxy = attrs.get("proxyAddresses") or []
        member_of = attrs.get("memberOf") or []
        if not isinstance(proxy, list):
            proxy = [proxy]
        if not isinstance(member_of, list):
            member_of = [member_of]

        return {
            "dn": entry.entry_dn,
            "object_guid": _guid_to_text(first("objectGUID")),
            "upn": str(first("userPrincipalName") or ""),
            "mail": str(first("mail") or ""),
            "sam_account_name": str(first("sAMAccountName") or ""),
            "first_name": str(first("givenName") or ""),
            "last_name": str(first("sn") or ""),
            "display_name": str(first("displayName") or ""),
            "computer_number": str(first(self.computer_number_attribute) or ""),
            "enabled": not bool(uac & 2),
            "proxy_addresses": [str(x) for x in proxy],
            "member_of": [str(x) for x in member_of],
        }

    def find_candidates(
        self,
        *,
        target_email: str,
        source_email: str,
        computer_number: str,
        first_name: str,
        last_name: str,
    ) -> list[dict]:
        emails = {x.strip().lower() for x in (target_email, source_email) if x and x.strip()}
        clauses = []
        for email in sorted(emails):
            escaped = escape_filter_chars(email)
            clauses.extend([
                f"(userPrincipalName={escaped})",
                f"(mail={escaped})",
                f"(proxyAddresses=smtp:{escaped})",
                f"(proxyAddresses=SMTP:{escaped})",
            ])
        if computer_number:
            clauses.append(
                f"({self.computer_number_attribute}={escape_filter_chars(computer_number.strip())})"
            )
        if target_email and "@" in target_email:
            local = target_email.split("@", 1)[0]
            if local:
                clauses.append(f"(sAMAccountName={escape_filter_chars(local[:20])})")

        if not clauses:
            return []

        search_filter = f"(&(objectCategory=person)(objectClass=user)(|{''.join(clauses)}))"
        attributes = [
            "distinguishedName",
            "objectGUID",
            "userPrincipalName",
            "mail",
            "proxyAddresses",
            "sAMAccountName",
            "givenName",
            "sn",
            "displayName",
            self.computer_number_attribute,
            "userAccountControl",
            "memberOf",
        ]
        conn = self._connect()
        try:
            conn.search(
                self.base_dn,
                search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                size_limit=25,
            )
            seen = set()
            rows = []
            for entry in conn.entries:
                item = self._entry_to_dict(entry)
                key = item["dn"].lower()
                if key not in seen:
                    seen.add(key)
                    rows.append(item)
            return rows
        finally:
            conn.unbind()

    def identity_decision(
        self,
        *,
        target_email: str,
        source_email: str,
        computer_number: str,
        first_name: str,
        last_name: str,
    ) -> dict:
        candidates = self.find_candidates(
            target_email=target_email,
            source_email=source_email,
            computer_number=computer_number,
            first_name=first_name,
            last_name=last_name,
        )

        expected_emails = {
            x.strip().lower() for x in (target_email, source_email) if x and x.strip()
        }
        expected_comp = _normalize_text(computer_number)
        expected_first = _normalize_text(first_name)
        expected_last = _normalize_text(last_name)

        exact = []
        scored = []
        for candidate in candidates:
            proxy = {
                str(x).split(":", 1)[-1].strip().lower()
                for x in candidate.get("proxy_addresses", [])
            }
            candidate_emails = {
                candidate.get("upn", "").strip().lower(),
                candidate.get("mail", "").strip().lower(),
                *proxy,
            }
            candidate_emails.discard("")
            email_match = bool(expected_emails & candidate_emails)
            comp_match = (
                bool(expected_comp)
                and _normalize_text(candidate.get("computer_number")) == expected_comp
            )
            name_match = (
                bool(expected_first)
                and bool(expected_last)
                and _normalize_text(candidate.get("first_name")) == expected_first
                and _normalize_text(candidate.get("last_name")) == expected_last
            )
            result = dict(candidate)
            result.update(
                {
                    "email_match": email_match,
                    "computer_number_match": comp_match,
                    "name_match": name_match,
                }
            )
            scored.append(result)
            if email_match and comp_match and name_match:
                exact.append(result)

        if len(exact) == 1:
            candidate = exact[0]
            if not candidate.get("enabled"):
                return {
                    "status": "manual_review",
                    "reason": "The identity matches, but the existing AD account is disabled.",
                    "candidates": scored,
                    "selected": candidate,
                }
            return {
                "status": "confirmed",
                "reason": "Email/UPN, Computer Number, and name match the same enabled AD object.",
                "candidates": scored,
                "selected": candidate,
            }

        if len(exact) > 1:
            return {
                "status": "manual_review",
                "reason": "Multiple AD objects satisfy all identity fields.",
                "candidates": scored,
            }

        if scored:
            return {
                "status": "manual_review",
                "reason": (
                    "AD returned one or more possible accounts, but email/UPN, Computer Number, "
                    "and name do not all match the same enabled AD object."
                ),
                "candidates": scored,
            }

        return {
            "status": "not_found",
            "reason": "No conflicting AD account was found by email/UPN, proxy address, Computer Number, or sAMAccountName.",
            "candidates": [],
        }

    def is_group_member(self, user_dn: str) -> bool:
        conn = self._connect()
        try:
            ok = conn.search(
                user_dn,
                "(objectClass=user)",
                search_scope=BASE,
                attributes=["memberOf"],
                size_limit=1,
            )
            if not ok or not conn.entries:
                raise RuntimeError("AD user could not be re-read for group validation")
            member_of = conn.entries[0].entry_attributes_as_dict.get("memberOf") or []
            if not isinstance(member_of, list):
                member_of = [member_of]
            wanted = _normalize_text(self.license_group_dn)
            return any(_normalize_text(str(group)) == wanted for group in member_of)
        finally:
            conn.unbind()

    def add_to_license_group(self, user_dn: str) -> None:
        conn = self._connect()
        try:
            if self.is_group_member(user_dn):
                return
            if not conn.modify(
                self.license_group_dn,
                {"member": [(MODIFY_ADD, [user_dn])]},
            ):
                raise RuntimeError(
                    "Could not add AD user to licensing group: "
                    + (conn.result.get("message") or str(conn.result))
                )
        finally:
            conn.unbind()

    def create_user(
        self,
        *,
        target_email: str,
        first_name: str,
        middle_name: str,
        last_name: str,
        computer_number: str,
        temporary_password: str,
        force_change_at_logon: bool = True,
    ) -> dict:
        if not target_email or "@" not in target_email:
            raise RuntimeError("A valid target email/UPN is required to create an AD user")
        if not first_name or not last_name or not computer_number:
            raise RuntimeError("First name, last name, and Computer Number are required")

        local, domain = target_email.split("@", 1)
        if self.upn_suffix and domain.lower() != self.upn_suffix.lower().lstrip("@"):
            raise RuntimeError(
                f"Target UPN suffix '{domain}' does not match configured suffix '{self.upn_suffix}'"
            )
        sam = re.sub(r"[^A-Za-z0-9._-]", "", local)[:20]
        if not sam:
            raise RuntimeError("Could not derive a safe sAMAccountName from target email")

        display = " ".join(x for x in [first_name.strip(), middle_name.strip(), last_name.strip()] if x)
        cn = escape_rdn(display)
        user_dn = f"CN={cn},{self.target_ou}"

        conn = self._connect()
        created = False
        try:
            attrs = {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "sAMAccountName": sam,
                "userPrincipalName": target_email,
                "givenName": first_name.strip(),
                "sn": last_name.strip(),
                "displayName": display,
                "mail": target_email,
                self.computer_number_attribute: computer_number.strip(),
                # Create disabled until password and group membership succeed.
                "userAccountControl": 514,
            }
            if middle_name.strip():
                attrs["initials"] = middle_name.strip()[:6]

            if not conn.add(user_dn, attributes=attrs):
                raise RuntimeError(
                    "Could not create AD user: " + (conn.result.get("message") or str(conn.result))
                )
            created = True

            if not conn.extend.microsoft.modify_password(user_dn, temporary_password):
                raise RuntimeError(
                    "AD user was created disabled, but the initial password could not be set: "
                    + (conn.result.get("message") or str(conn.result))
                )

            if not conn.modify(
                self.license_group_dn,
                {"member": [(MODIFY_ADD, [user_dn])]},
            ):
                raise RuntimeError(
                    "AD user was created disabled, but could not be added to the licensing group: "
                    + (conn.result.get("message") or str(conn.result))
                )

            changes = {
                "userAccountControl": [(MODIFY_REPLACE, [512])],
            }
            if force_change_at_logon:
                changes["pwdLastSet"] = [(MODIFY_REPLACE, [0])]
            if not conn.modify(user_dn, changes):
                raise RuntimeError(
                    "AD user was created but could not be enabled/finalized: "
                    + (conn.result.get("message") or str(conn.result))
                )

            decision = self.identity_decision(
                target_email=target_email,
                source_email=target_email,
                computer_number=computer_number,
                first_name=first_name,
                last_name=last_name,
            )
            selected = decision.get("selected") or {"dn": user_dn}
            return {
                "ok": True,
                "created": True,
                "dn": selected.get("dn", user_dn),
                "object_guid": selected.get("object_guid", ""),
                "sam_account_name": sam,
            }
        except Exception:
            # Never auto-delete a partially provisioned account. If creation
            # occurred, it remains disabled unless every critical step succeeded.
            raise
        finally:
            conn.unbind()
