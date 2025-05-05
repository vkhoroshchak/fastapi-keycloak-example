import asyncio
import hashlib
import json
import time

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from jwt import PyJWK, PyJWKClientError
from keycloak.exceptions import KeycloakError
from redis.exceptions import RedisError

from app.core.clients import jwks_client, keycloak_client, redis_client
from app.core.config import settings
from src.app.core.logging import Logger, get_logger

logger: Logger = get_logger(__name__)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=settings.authorization_url,
    tokenUrl=settings.token_url,
    auto_error=False,  # Set to False to handle missing/invalid token manually if needed, True raises HTTPException directly
)


def generate_cache_key(token: str) -> str:
    """Generates a secure cache key for a token."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return f"{settings.REDIS_PREFIX}token_info:{token_hash}"


def build_www_authenticate_header(error: str = "invalid_token", description: str | None = None) -> str:
    """Builds the WWW-Authenticate header string."""
    header = f'Bearer realm="{settings.KEYCLOAK_REALM}", error="{error}"'
    if description:
        header += f', error_description="{description}"'
    return header


class AuthenticationError(HTTPException):
    """Custom exception for authentication failures, pre-configured with status code."""

    def __init__(self, detail: str, description: str | None = None, status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.status_code = status_code
        headers = {"WWW-Authenticate": build_www_authenticate_header(description=description)}
        super().__init__(status_code=self.status_code, detail=detail, headers=headers)


async def get_cached_token_info(token_cache_key: str) -> dict | None:
    """Retrieves and validates token info from the Redis cache."""
    try:
        cached_data_str = await redis_client.get(token_cache_key)
        if not cached_data_str:
            return None

        cached_info = json.loads(cached_data_str)
        if not isinstance(cached_info, dict) or "exp" not in cached_info or "sub" not in cached_info:
            logger.warning(f"Invalid data structure in cache for key: {token_cache_key}")
            await redis_client.delete(token_cache_key)
            return None

        if time.time() < cached_info["exp"]:
            logger.debug(f"Returning cached token info for key: {token_cache_key}")
            return cached_info
        else:
            logger.debug(f"Cached token expired for key: {token_cache_key}")
            await redis_client.delete(token_cache_key)
            return None

    except json.JSONDecodeError:
        logger.warning(f"Failed to decode cached data for key: {token_cache_key}. Invalidating.")
        await redis_client.delete(token_cache_key)
        return None
    except RedisError as e:
        logger.error(f"Redis cache read error for key {token_cache_key}: {e}")
        return None  # Treat redis error as cache miss for now.


async def get_signing_key(token: str) -> PyJWK:
    """Fetches and returns the signing key from the JWKS endpoint."""
    try:
        unverified_header = jwt.get_unverified_header(token)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        logger.debug(f"Obtained signing key for kid: {unverified_header.get('kid')}")
        return signing_key
    except PyJWKClientError as e:
        logger.error(f"Failed to get signing key from JWKS ({settings.jwks_url}): {e}")
        raise AuthenticationError(
            detail="Cannot retrieve signing keys. Authentication service may be down.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from e
    except JWTError as e:
        logger.warning(f"Invalid token header or format: {e}")
        raise AuthenticationError(
            detail="Invalid token format.",
            description="Malformed token header",
        ) from e


async def decode_and_validate_token(token: str, signing_key: PyJWK) -> dict:
    """Decodes and validates the token using the provided signing key."""

    expected_audience = "account"
    expected_issuer = f"{str(settings.KEYCLOAK_SERVER_URL).rstrip('/')}/realms/{settings.KEYCLOAK_REALM}"

    try:
        token_info = jwt.decode(
            token,
            signing_key.key,
            algorithms=[settings.KEYCLOAK_ALGORITHM],
            audience=expected_audience,
            issuer=expected_issuer,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["exp", "iat", "sub"],  # Standard required claims
            },
        )
        logger.debug(f"Token signature and claims verified locally for sub: {token_info.get('sub')}")
        return token_info

    except jwt.ExpiredSignatureError as e:
        raise AuthenticationError(detail="Token has expired", description="Token has expired") from e
    except JWTError as e:
        error_msg = str(e)
        logger.warning(f"JWT validation error: {error_msg}")

        if "audience" in error_msg.lower():
            detail = "Invalid audience"
            error_desc = "Invalid audience"
        elif "issuer" in error_msg.lower():
            detail = "Invalid issuer"
            error_desc = "Invalid issuer"
        elif "claim" in error_msg.lower() and "missing" in error_msg.lower():
            detail = "Token missing required claim"
            error_desc = "Missing required claim"
        else:
            detail = "Invalid token"
            error_desc = "Token validation failed"

        raise AuthenticationError(detail=detail, description=error_desc) from e


async def introspect_token(token: str, token_info: dict) -> None:
    """Performs token introspection against Keycloak."""
    keycloak_openid = keycloak_client
    logger.debug(f"Performing token introspection for sub: {token_info.get('sub')}")

    try:
        introspection_result = await asyncio.to_thread(keycloak_openid.introspect, token)

        if not introspection_result.get("active", False):
            logger.warning(f"Token introspection returned inactive for sub: {token_info.get('sub')}")
            raise AuthenticationError(
                detail="Token is not active or has been revoked.", description="Token inactive or revoked"
            )
        logger.debug("Token introspection successful (active).")

    except KeycloakError as ke:
        log_msg = f"Keycloak introspection error: {ke}"
        if hasattr(ke, "response_code"):
            log_msg += f" (Status Code: {ke.response_code})"
        if hasattr(ke, "response_body"):
            log_msg += f" (Details: {ke.response_body})"
        logger.error(log_msg)
        raise AuthenticationError(
            detail="Token validation service (introspection) unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from ke
    except Exception as e:
        logger.exception(f"Unexpected error during token introspection: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during secondary token validation.",
        ) from e


async def cache_token_info(token_cache_key: str, token_info: dict) -> None:
    """Caches the validated token information in Redis."""
    try:
        now = int(time.time())
        expires_at = token_info.get("exp", 0)
        ttl_seconds = max(0, expires_at - now)
        ttl_seconds = min(ttl_seconds, settings.TOKEN_CACHE_TIMEOUT_SECONDS)

        if ttl_seconds > 5:
            token_info_str = json.dumps(token_info)
            await redis_client.set(token_cache_key, token_info_str, ex=ttl_seconds)
            logger.debug(f"Cached validated token info for key {token_cache_key} with TTL {ttl_seconds}s")
        else:
            logger.debug(f"Token expires too soon (or already expired), not caching: {token_cache_key}")

    except RedisError as cache_err:
        logger.error(f"Redis cache write error for key {token_cache_key}: {cache_err}")
    except Exception as e:
        logger.error(f"Failed to serialize token info for caching: {e}")


async def verify_token(token: str | None = Depends(oauth2_scheme)) -> dict:
    """
    Dependency to verify the JWT token received in the Authorization header.

    1. Checks for token presence.
    2. Checks Redis cache for previously validated token info.
    3. Fetches signing key from Keycloak's JWKS endpoint (cached by PyJWKClient).
    4. Decodes and validates the token signature and standard claims (exp, iss, aud).
    5. Optionally performs token introspection via Keycloak.
    6. Caches the validated token payload in Redis.

    Raises HTTPException(401) or HTTPException(403) on errors.
    Raises HTTPException(503) if JWKS/Introspection endpoint is unavailable.
    """
    if token is None:
        logger.warning("Attempt to access protected route without token.")
        raise AuthenticationError(detail="Not authenticated", description="Authentication token required")

    token_cache_key = generate_cache_key(token)

    # 1. Check Cache First
    cached_info = await get_cached_token_info(token_cache_key)
    if cached_info:
        return cached_info

    logger.debug("Token info not in cache or expired/invalid, verifying token...")

    try:
        # 2. Get Signing Key from JWKS
        signing_key = await get_signing_key(token)

        # 3. Decode and Validate Token Locally
        token_info = await decode_and_validate_token(token, signing_key)

        # 4. Optional: Token Introspection (if configured)
        if settings.PERFORM_INTROSPECTION:
            await introspect_token(token, token_info)

        # 5. Cache the Validated Token Information
        await cache_token_info(token_cache_key, token_info)

        # 6. Return the validated token payload
        return token_info

    except AuthenticationError as e:
        raise e  # Re-raise authentication errors
    except HTTPException as e:
        raise e  # Re-raise HTTPException errors
    except Exception as e:
        logger.exception(f"Unexpected critical error during token verification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication process.",
        ) from e


# --- Role Checking Dependency ---
# Takes required roles and returns a dependency function
def require_role(required_roles: list[str] | None = None, require_all: bool = True) -> callable:
    """
    Dependency factory for checking user roles.

    Args:
        required_roles: A list of role names required. If None or empty, allows any authenticated user.
        require_all: If True, user must have all roles. If False, user must have at least one.

    Returns:
        An async dependency function that verifies roles based on the token.
    """

    async def role_checker(token_data: dict = Depends(verify_token)) -> dict:
        """The actual dependency function returned by require_role"""
        if not required_roles:
            # No specific roles required, just authentication
            return token_data

        # Extract roles reliably, handling missing keys/structures
        realm_access = token_data.get("realm_access", {})
        realm_roles = set(realm_access.get("roles", []))

        resource_access = token_data.get("resource_access", {})
        client_roles = set()
        # Roles might be under client_id or just directly in resource_access
        if settings.KEYCLOAK_CLIENT_ID in resource_access:
            client_roles = set(resource_access[settings.KEYCLOAK_CLIENT_ID].get("roles", []))
        # Example: Check roles for another client 'account' if needed
        # account_roles = set(resource_access.get("account", {}).get("roles", []))

        # Combine all relevant roles
        # Modify this logic if you need roles from other clients as well
        user_roles = realm_roles.union(client_roles)
        logger.debug(f"User sub: {token_data.get('sub')} has roles: {user_roles}")

        required_set = set(required_roles)
        has_permission = False

        if require_all:
            has_permission = required_set.issubset(user_roles)
            if not has_permission:
                missing_roles = required_set.difference(user_roles)
                logger.warning(
                    f"Permission denied for sub: {token_data.get('sub')}. Missing required roles: {missing_roles}"
                )
        else:
            has_permission = not required_set.isdisjoint(user_roles)  # Check for any intersection
            if not has_permission:
                logger.warning(
                    f"Permission denied for sub: {token_data.get('sub')}. Needs at least one of: {required_roles}"
                )

        if not has_permission:
            role_desc = "all of" if require_all else "at least one of"
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Requires {role_desc}: {', '.join(required_roles)}",
            )

        return token_data

    return role_checker
