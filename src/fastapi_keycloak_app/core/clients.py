from functools import lru_cache

from jwt import PyJWKClient
from keycloak import KeycloakOpenID
from redis import asyncio as aioredis

from fastapi_keycloak_app.core.config import settings
from src.fastapi_keycloak_app.core.logging import Logger, get_logger

logger: Logger = get_logger(__name__)

redis_client = aioredis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=None,
    decode_responses=True,
    socket_connect_timeout=2,
    socket_timeout=2,
    health_check_interval=30,
)


@lru_cache
def get_keycloak_openid() -> KeycloakOpenID:
    return KeycloakOpenID(
        server_url=settings.KEYCLOAK_SERVER_URL,
        client_id=settings.KEYCLOAK_CLIENT_ID,
        realm_name=settings.KEYCLOAK_REALM,
        client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
        verify=True,
    )


keycloak_client = get_keycloak_openid()


try:
    jwks_client = PyJWKClient(
        settings.jwks_url,
        cache_jwk_set=True,
        lifespan=settings.JWKS_CACHE_TIMEOUT_SECONDS,
        # Add timeout for the HTTP request to fetch JWKS
        # Requires PyJWKClient >= 2.3.0 with httpx support
        # client_options={"timeout": 5.0} # Example: 5 second timeout
    )
    logger.info(f"JWKS client configured for URL: {settings.jwks_url}")
except Exception as e:
    logger.critical(f"Failed to initialize JWKS client: {e}")
    # Application may not be able to validate tokens
    raise SystemExit(f"CRITICAL: Failed to initialize JWKS client: {e}") from e
