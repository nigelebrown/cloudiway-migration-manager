import asyncio
from urllib.parse import quote

import httpx


class MicrosoftGraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, required_sku: str = ""):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.required_sku = (required_sku or "").strip().lower()
        self._token: str | None = None

    async def _access_token(self) -> str:
        if self._token:
            return self._token
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise RuntimeError("Microsoft Graph settings are incomplete")
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
        if response.status_code >= 400:
            raise RuntimeError(
                f"Microsoft Graph token request failed ({response.status_code}): {response.text[:500]}"
            )
        data = response.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError("Microsoft Graph token response did not contain access_token")
        self._token = token
        return token

    async def _get(self, path: str, allow_not_found: bool = False):
        token = await self._access_token()
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0" + path,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
        if allow_not_found and response.status_code in (400, 404):
            return None
        if response.status_code >= 400:
            raise RuntimeError(
                f"Microsoft Graph GET {path} failed ({response.status_code}): {response.text[:700]}"
            )
        return response.json()

    async def test_connection(self) -> dict:
        data = await self._get("/organization?$select=id,displayName")
        values = data.get("value") or []
        return {
            "ok": True,
            "organizations": [
                {"id": x.get("id"), "displayName": x.get("displayName")} for x in values[:5]
            ],
        }

    async def get_user(self, upn: str) -> dict | None:
        encoded = quote(upn.strip(), safe="")
        data = await self._get(
            f"/users/{encoded}?$select=id,userPrincipalName,mail,displayName,accountEnabled,assignedLicenses",
            allow_not_found=True,
        )
        if not data:
            return None
        return data

    async def get_license_details(self, object_id: str) -> list[dict]:
        data = await self._get(
            f"/users/{quote(object_id, safe='')}/licenseDetails?$select=skuId,skuPartNumber"
        )
        return data.get("value") or []

    async def license_ready(self, object_id: str) -> tuple[bool, list[str]]:
        details = await self.get_license_details(object_id)
        sku_names = [str(x.get("skuPartNumber") or "") for x in details]
        if not self.required_sku:
            return bool(details), sku_names
        return any(x.lower() == self.required_sku for x in sku_names), sku_names

    async def mailbox_ready(self, object_id: str) -> tuple[bool, str]:
        # mailboxSettings is an inexpensive readiness check. A mailbox that is
        # not yet provisioned typically returns a 4xx rather than mailbox data.
        token = await self._access_token()
        path = f"/users/{quote(object_id, safe='')}/mailboxSettings"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0" + path,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
        if response.status_code == 200:
            return True, "Mailbox settings are available"
        if response.status_code in (400, 404):
            try:
                data = response.json()
                detail = (
                    data.get("error", {}).get("message")
                    or data.get("error", {}).get("code")
                    or response.text[:300]
                )
            except Exception:
                detail = response.text[:300]
            return False, str(detail)
        raise RuntimeError(
            f"Microsoft Graph mailbox check failed ({response.status_code}): {response.text[:500]}"
        )
