from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_admin_password: str
    app_encryption_key: str
    session_secret: str

    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_name: str = "cloudiway_migration"
    db_user: str = "cloudiway"
    db_password: str = ""

    cloudiway_base_url: str = "https://api-production.cloudiway.com/ap1"
    cloudiway_project_header: str = "JCF"
    cloudiway_product_type_mail: int = 5
    cloudiway_job_type_audit: int = 30
    cloudiway_job_type_migration: int = 33

    rackspace_base_url: str = "https://api.emailsrvr.com/v1"

    pilot_size: int = 5
    batch_size: int = 10
    status_poll_seconds: int = 15
    progress_window_minutes: int = 1
    batch_timeout_minutes: int = 1440
    auto_continue: bool = True
    pause_on_any_failure: bool = True
    session_https_only: bool = True
    login_max_attempts: int = 5
    login_window_seconds: int = 300

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
