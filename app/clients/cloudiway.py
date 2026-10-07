from typing import Any
import httpx
from app.config import settings
from app.diagnostics import log_info, log_error


class CloudiwayClient:
    def __init__(self, token: str | None = None, project_header: str | None = None):
        self.token = token
        self.project_header = project_header or settings.cloudiway_project_header

    def _headers(self, include_project: bool = True) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if include_project and self.project_header:
            headers["projectId"] = str(self.project_header)
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def login(self, username: str, password: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.post(
                f"{settings.cloudiway_base_url}/Authentication/Login",
                headers={"projectId": self.project_header, "accept": "application/json"},
                json={"login": username, "password": password, "keepConnection": True},
            )
        self._raise(r, "Cloudiway login failed")
        data = r.json()
        self.token = data.get("token")
        return data

    async def refresh_token(self, token: str, refresh_token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.post(
                f"{settings.cloudiway_base_url}/Authentication/RefreshToken",
                headers={"projectId": self.project_header, "accept": "application/json"},
                json={"token": token, "refreshToken": refresh_token},
            )
        self._raise(r, "Cloudiway token refresh failed")
        return r.json()

    async def projects(self, include_project_header: bool = False):
        return await self._get(
            "/Projects",
            "Could not retrieve Cloudiway projects",
            include_project=include_project_header,
        )

    async def connectors(self):
        return await self._get("/Connectors", "Could not retrieve Cloudiway connectors")

    async def connector_pools(self):
        return await self._get("/ConnectorsPool", "Could not retrieve Cloudiway connector pools")

    async def mail_users(self):
        return await self._get("/Mail", "Could not retrieve Cloudiway mail users")

    async def get_mail_user(self, object_id: int):
        return await self._get(f"/Mail/{object_id}", "Could not retrieve Cloudiway mail user")

    async def create_mail_user(self, payload: dict[str, Any]):
        return await self._post("/Mail", payload, "Could not create Cloudiway mail user")

    async def update_mail_user(self, object_id: int, payload: dict[str, Any]):
        return await self._put(f"/Mail/{object_id}", payload, "Could not update Cloudiway mail user")

    async def verify_mail_user(self, email: str):
        return await self._get(f"/Mail/VerifyMailUser/{email}", "Could not verify Cloudiway mail user")

    async def get_self_service_token(self, object_id: int):
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.get(
                f"{settings.cloudiway_base_url}/MailSelfService/token",
                headers=self._headers(),
                params={"objectId": object_id},
            )
        self._raise(r, "Could not obtain Cloudiway self-service token")
        data = r.json() if r.content else {}
        return self._extract_token(data)

    async def register_source_credentials(self, token: str, username: str, password: str):
        payload = {"userName": username, "password": password}
        return await self._post(
            f"/MailSelfService/{token}",
            payload,
            "Could not register Cloudiway source credentials",
        )

    async def start_migration(self, object_ids: list[int]):
        return await self._post(
            f"/Jobs/StartJobs/{settings.cloudiway_product_type_mail}/{settings.cloudiway_job_type_migration}",
            object_ids,
            "Could not start Cloudiway migration",
        )

    async def start_audit(self, object_ids: list[int]):
        return await self._post(
            f"/Jobs/StartJobs/{settings.cloudiway_product_type_mail}/{settings.cloudiway_job_type_audit}",
            object_ids,
            "Could not start Cloudiway audit",
        )

    async def progress(self, object_id: int, since_minutes: int = 15):
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.get(
                f"{settings.cloudiway_base_url}/Mail/MailProgress/{object_id}",
                headers=self._headers(),
                params={"sinceMinutes": since_minutes},
            )
        self._raise(r, "Could not retrieve Cloudiway migration progress")
        return r.json() if r.content else {}

    async def audit(self, object_id: int):
        return await self._get(f"/Mail/Audit/{object_id}", "Could not retrieve Cloudiway audit")

    async def logs(self, object_id: int):
        return await self._get(f"/Mail/logs/{object_id}", "Could not retrieve Cloudiway logs")

    async def _get(self, path: str, error: str, include_project: bool = True):
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.get(
                f"{settings.cloudiway_base_url}{path}",
                headers=self._headers(include_project=include_project),
            )
        self._raise(r, error)
        return r.json() if r.content else {}

    async def _post(self, path: str, payload: Any, error: str):
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(
                f"{settings.cloudiway_base_url}{path}", headers=self._headers(), json=payload
            )
        self._raise(r, error)
        return r.json() if r.content else {}

    async def _put(self, path: str, payload: Any, error: str):
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.put(
                f"{settings.cloudiway_base_url}{path}", headers=self._headers(), json=payload
            )
        self._raise(r, error)
        return r.json() if r.content else {}

    @staticmethod
    def _raise(response: httpx.Response, prefix: str):
        log_info("cloudiway_api_response", method=response.request.method, url=str(response.request.url), status=response.status_code)
        if response.status_code >= 400:
            log_error("cloudiway_api_failed", method=response.request.method, url=str(response.request.url), status=response.status_code, body=response.text[:700])
            raise RuntimeError(
                f"{prefix} ({response.status_code}) [{response.request.method} {response.request.url}]: "
                f"{response.text[:1000]}"
            )

    @staticmethod
    def _extract_token(data: Any) -> str:
        if isinstance(data, str):
            return data.strip('"')
        if isinstance(data, dict):
            for key in ("token", "responseData", "data"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    return value
                if isinstance(value, dict):
                    nested = value.get("token")
                    if nested:
                        return nested
        raise RuntimeError(f"Cloudiway self-service token was not present in response: {data}")
