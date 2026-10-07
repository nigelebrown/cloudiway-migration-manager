import base64
import hashlib
from datetime import datetime, timezone

import httpx

from app.config import settings


class RackspaceClient:
    USER_AGENT = "JCF-Cloudiway-Migration-Manager/1.0"
    IDENTITY_URL = "https://identity.api.rackspacecloud.com/v2.0/tokens"

    def __init__(
        self,
        user_key: str = "",
        secret_key: str = "",
        customer_id: str = "",
        *,
        auth_mode: str = "api_key",
        username: str = "",
        password: str = "",
    ):
        self.auth_mode = (auth_mode or "api_key").strip()
        self.user_key = (user_key or "").strip()
        self.secret_key = (secret_key or "").strip()
        self.customer_id = (customer_id or "").strip()
        self.username = (username or "").strip()
        self.password = password or ""
        self.identity_token: str | None = None
        self.identity_expires: str | None = None

    def _signature_headers(self) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        to_sign = f"{self.user_key}{self.USER_AGENT}{timestamp}{self.secret_key}".encode()
        digest = hashlib.sha1(to_sign).digest()
        signature = base64.b64encode(digest).decode()
        return {
            "User-Agent": self.USER_AGENT,
            "X-Api-Signature": f"{self.user_key}:{timestamp}:{signature}",
            "Accept": "application/json",
        }

    # Backwards-compatible name used by existing unit tests.
    def _headers(self) -> dict[str, str]:
        return self._signature_headers()

    async def authenticate_identity(self) -> dict:
        if not self.username or not self.password:
            raise RuntimeError("Rackspace username and password are required")

        payload = {
            "auth": {
                "passwordCredentials": {
                    "username": self.username,
                    "password": self.password,
                }
            }
        }
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                self.IDENTITY_URL,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=payload,
            )
        if r.status_code >= 400:
            raise RuntimeError(self._error("Rackspace username/password authentication failed", r))

        data = r.json()
        access = data.get("access") or {}
        token = access.get("token") or {}
        token_id = token.get("id")
        if not token_id:
            raise RuntimeError("Rackspace authentication succeeded but no X-Auth-Token was returned")

        self.identity_token = token_id
        self.identity_expires = token.get("expires")
        return {
            "ok": True,
            "username": self.username,
            "expires": self.identity_expires,
            "tenant": token.get("tenant"),
            "serviceCatalog": access.get("serviceCatalog") or [],
        }

    async def _email_headers(self) -> dict[str, str]:
        if self.auth_mode == "username_password":
            if not self.identity_token:
                await self.authenticate_identity()
            return {
                "User-Agent": self.USER_AGENT,
                "X-Auth-Token": self.identity_token,
                "Accept": "application/json",
            }
        return self._signature_headers()

    def _mailbox_url(self, email: str) -> str:
        if not self.customer_id:
            raise RuntimeError(
                "Rackspace Customer Account Number/RAN is required for mailbox administration"
            )
        mailbox, domain = email.split("@", 1)
        return (
            f"{settings.rackspace_base_url}/customers/{self.customer_id}"
            f"/domains/{domain}/rs/mailboxes/{mailbox}"
        )

    async def test_connection(self) -> dict:
        if self.auth_mode == "username_password":
            identity = await self.authenticate_identity()
            if not self.customer_id:
                return {
                    "ok": True,
                    "identity_authenticated": True,
                    "mailbox_admin_verified": False,
                    "message": (
                        "Rackspace username/password authentication succeeded. "
                        "Enter the Customer Account Number/RAN to test whether this token "
                        "is also accepted by the Rackspace Email administration API."
                    ),
                    "expires": identity.get("expires"),
                }

            url = f"{settings.rackspace_base_url}/customers/{self.customer_id}/domains"
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(url, headers=await self._email_headers())

            if r.status_code in (401, 403):
                return {
                    "ok": True,
                    "identity_authenticated": True,
                    "mailbox_admin_verified": False,
                    "message": (
                        "Rackspace username/password authentication succeeded, but the "
                        "Cloud Office Email API did not accept the Identity token for mailbox "
                        "administration. This account will require the Rackspace Email API "
                        "User Key/Secret Key for automated password resets."
                    ),
                    "status_code": r.status_code,
                }
            if r.status_code >= 400:
                raise RuntimeError(self._error("Rackspace mailbox administration test failed", r))

            return {
                "ok": True,
                "identity_authenticated": True,
                "mailbox_admin_verified": True,
                "message": (
                    "Rackspace username/password authentication succeeded and the token "
                    "was accepted by the Email administration API."
                ),
            }

        if not self.user_key or not self.secret_key or not self.customer_id:
            raise RuntimeError(
                "Rackspace Email API User Key, Secret Key and Customer Account Number are required"
            )

        url = f"{settings.rackspace_base_url}/customers/{self.customer_id}/domains"
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(url, headers=self._signature_headers())
        if r.status_code >= 400:
            raise RuntimeError(self._error("Rackspace Email API connection test failed", r))
        return {
            "ok": True,
            "identity_authenticated": False,
            "mailbox_admin_verified": True,
            "message": "Rackspace Email API credentials are valid for mailbox administration.",
        }

    async def get_mailbox(self, email: str) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(self._mailbox_url(email), headers=await self._email_headers())
        if r.status_code >= 400:
            if self.auth_mode == "username_password" and r.status_code in (401, 403):
                raise RuntimeError(
                    "Rackspace username/password authenticated, but the Email administration "
                    "API rejected the token. Configure Rackspace Email API keys for automated "
                    "mailbox password resets."
                )
            raise RuntimeError(self._error(f"Rackspace mailbox lookup failed for {email}", r))
        return r.json() if r.content else {}

    async def reset_password(self, email: str, new_password: str) -> None:
        headers = await self._email_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.put(
                self._mailbox_url(email),
                headers=headers,
                data={"password": new_password},
            )
        if r.status_code not in (200, 202, 204):
            if self.auth_mode == "username_password" and r.status_code in (401, 403):
                raise RuntimeError(
                    "Rackspace Identity authentication succeeded, but this token is not "
                    "authorized to reset Cloud Office mailbox passwords. Configure Rackspace "
                    "Email API keys instead."
                )
            raise RuntimeError(self._error(f"Rackspace password reset failed for {email}", r))

    @staticmethod
    def _error(prefix: str, response: httpx.Response) -> str:
        detail = response.headers.get("x-error-message") or response.text[:800]
        return f"{prefix} ({response.status_code}): {detail}"
