from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_admin_password: str
    app_encryption_key: str
    session_secret: str
    database_path: str = "data/migration.db"

    cloudiway_base_url: str = "https://api-production.cloudiway.com/ap1"
    cloudiway_project_header: str = "JCF"
    cloudiway_product_type_mail: int = 5
    cloudiway_job_type_audit: int = 30
    cloudiway_job_type_migration: int = 33

    rackspace_base_url: str = "https://api.emailsrvr.com/v1"

    pilot_size: int = 5
    batch_size: int = 10
    status_poll_seconds: int = 15
    auto_continue: bool = True
    pause_on_any_failure: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
