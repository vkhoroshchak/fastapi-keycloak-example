import secrets
from functools import lru_cache

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.fastapi_keycloak_app.core.logging import Logger, get_logger

logger: Logger = get_logger(__name__)


class Settings(BaseSettings):
    """Application Configuration"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,  # Environment variables are often uppercase
    )

    APP_NAME: str = "FastAPI Keycloak Integration"
    API_VERSION: str = "v1"
    DEBUG: bool = Field(default=False, validation_alias="DEBUG")

    # Keycloak Settings
    # Public facing URL of Keycloak
    KEYCLOAK_SERVER_URL: HttpUrl = Field(default="http://localhost:8080", validation_alias="KEYCLOAK_SERVER_URL")
    # URL for server-to-server communication (e.g., within Docker/K8s), often without external proxy/LB
    # Defaults to KEYCLOAK_SERVER_URL if not set
    KEYCLOAK_INTERNAL_URL: HttpUrl | None = Field(
        default="http://keycloak:8080", validation_alias="KEYCLOAK_INTERNAL_URL"
    )
    KEYCLOAK_REALM: str = Field(default="master", validation_alias="KEYCLOAK_REALM")
    KEYCLOAK_CLIENT_ID: str = Field(default="fastapi-client", validation_alias="KEYCLOAK_CLIENT_ID")
    # Required only for confidential clients / certain flows (refresh, introspection, revocation)
    KEYCLOAK_CLIENT_SECRET: str | None = Field(default=None, validation_alias="KEYCLOAK_CLIENT_SECRET")
    # Recommended: Let Keycloak dictate via JWKS. If overridden, ensure it matches Keycloak's keys.
    KEYCLOAK_ALGORITHM: str = Field(default="RS256", validation_alias="KEYCLOAK_ALGORITHM")
    # Audience claim expected in the JWT. Often the client_id or a specific API identifier.
    # Set to None to disable audience check if Keycloak doesn't include 'aud' or validation isn't desired here.
    # If set, the token MUST contain this value in its 'aud' claim.
    EXPECTED_AUDIENCE: str | None = Field(default=None, validation_alias="EXPECTED_AUDIENCE")
    # Should we perform token introspection in addition to local validation? Increases security but adds latency.
    PERFORM_INTROSPECTION: bool = Field(default=False, validation_alias="PERFORM_INTROSPECTION")

    # Security & CORS
    # Ensure this matches your frontend URL(s). Use ["*"] cautiously.
    ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"],
        validation_alias="ALLOWED_ORIGINS",
    )
    # Used for signing session cookies (primarily for Swagger OAuth state). Generate a strong random key.
    SESSION_SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        validation_alias="SESSION_SECRET_KEY",
    )
    # Set to True in production behind HTTPS proxy
    SESSION_COOKIE_HTTPS_ONLY: bool = Field(default=False, validation_alias="SESSION_COOKIE_HTTPS_ONLY")

    # Caching
    JWKS_CACHE_TIMEOUT_SECONDS: int = Field(default=3600, validation_alias="JWKS_CACHE_TIMEOUT_SECONDS")
    TOKEN_CACHE_TIMEOUT_SECONDS: int = Field(default=300, validation_alias="TOKEN_CACHE_TIMEOUT_SECONDS")

    # Redis Configuration
    REDIS_HOST: str = Field(default="localhost", validation_alias="REDIS_HOST")
    REDIS_PORT: int = Field(default=6379, validation_alias="REDIS_PORT")
    REDIS_DB: int = Field(default=0, validation_alias="REDIS_DB")
    REDIS_PASSWORD: str | None = Field(default=None, validation_alias="REDIS_PASSWORD")
    # Prefix keys to avoid collisions if Redis is shared
    REDIS_PREFIX: str = Field(default="fastapi-keycloak:", validation_alias="REDIS_PREFIX")
    REDIS_CONNECT_TIMEOUT: int = Field(default=2, validation_alias="REDIS_CONNECT_TIMEOUT")  # seconds
    REDIS_SOCKET_TIMEOUT: int = Field(default=2, validation_alias="REDIS_SOCKET_TIMEOUT")  # seconds

    # Logging
    LOG_LEVEL: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    ENVIRONMENT: str = Field(default="development", validation_alias="ENVIRONMENT")

    # Database Configuration
    DATABASE_URL: str

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def keycloak_base_url(self) -> str:
        return f"{self.KEYCLOAK_SERVER_URL}realms/{self.KEYCLOAK_REALM}"

    @property
    def keycloak_internal_base_url(self) -> str:
        # Use internal URL if provided, otherwise fall back to public URL
        url = self.KEYCLOAK_INTERNAL_URL or self.KEYCLOAK_SERVER_URL
        return f"{url}realms/{self.KEYCLOAK_REALM}"

    @property
    def authorization_url(self) -> str:
        return f"{self.keycloak_base_url}/protocol/openid-connect/auth"

    @property
    def token_url(self) -> str:
        return f"{self.keycloak_base_url}/protocol/openid-connect/token"

    @property
    def jwks_url(self) -> str:
        # Use internal base URL for server-to-server JWKS fetching
        return f"{self.keycloak_internal_base_url}/protocol/openid-connect/certs"

    @property
    def userinfo_url(self) -> str:
        return f"{self.keycloak_base_url}/protocol/openid-connect/userinfo"

    @property
    def logout_url(self) -> str:
        return f"{self.keycloak_base_url}/protocol/openid-connect/logout"

    @property
    def revoke_url(self) -> str:
        # Use internal base URL for server-to-server revocation
        return f"{self.keycloak_internal_base_url}/protocol/openid-connect/revoke"

    @property
    def effective_audience(self) -> str | None:
        # Prioritize explicit setting, fallback to client_id if not set
        return self.EXPECTED_AUDIENCE if self.EXPECTED_AUDIENCE is not None else self.KEYCLOAK_CLIENT_ID


@lru_cache
def get_settings() -> Settings:
    logger.info("Loading application settings...")
    try:
        settings = Settings()
        # Log key settings (avoiding secrets)
        logger.info(f"Application Name: {settings.APP_NAME}")
        logger.info(f"Keycloak Server URL: {settings.KEYCLOAK_SERVER_URL}")
        logger.info(f"Keycloak Internal URL: {settings.KEYCLOAK_INTERNAL_URL or 'Not Set (uses Server URL)'}")
        logger.info(f"Keycloak Realm: {settings.KEYCLOAK_REALM}")
        logger.info(f"Keycloak Client ID: {settings.KEYCLOAK_CLIENT_ID}")
        logger.info(f"Keycloak Client Secret Set: {'Yes' if settings.KEYCLOAK_CLIENT_SECRET else 'No'}")
        logger.info(f"Effective Audience: {settings.effective_audience or 'Disabled'}")
        logger.info(f"Perform Introspection: {settings.PERFORM_INTROSPECTION}")
        logger.info(f"Redis Host: {settings.REDIS_HOST}")
        logger.info(f"Allowed Origins: {settings.ALLOWED_ORIGINS}")
        return settings
    except Exception as e:
        logger.critical(f"Failed to load settings: {e}")
        raise SystemExit(f"CRITICAL: Failed to load settings: {e}") from e


settings = get_settings()
