import asyncio
import json

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from keycloak.exceptions import KeycloakError
from redis.exceptions import RedisError

from app.auth.schemas import RefreshRequest, RevokeRequest
from app.core.clients import get_keycloak_openid, redis_client
from app.core.config import settings
from app.core.security import generate_cache_key
from src.app.core.logging import Logger, get_logger

logger: Logger = get_logger(__name__)

router = APIRouter()


@router.post("/api/auth/refresh", summary="Refresh access token")
async def refresh_token_endpoint(request: RefreshRequest):
    """Exchanges a valid refresh token for a new access token and refresh token."""
    if not request.refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token is required.")

    keycloak_openid = get_keycloak_openid()
    try:
        logger.info("Attempting token refresh...")
        # Run blocking call in thread
        token_response = await asyncio.to_thread(keycloak_openid.refresh_token, request.refresh_token)
        logger.info("Token refresh successful.")
        # Return the new tokens
        return token_response
    except KeycloakError as e:
        logger.error(f"Token refresh failed: {e}")
        error_detail = "Invalid refresh token or client configuration issue."
        status_code = status.HTTP_401_UNAUTHORIZED  # Default to 401
        if hasattr(e, "response_code"):
            status_code = e.response_code
        if hasattr(e, "response_body"):
            try:
                # Attempt to parse Keycloak error response
                body = json.loads(e.response_body.decode()) if isinstance(e.response_body, bytes) else e.response_body
                if isinstance(body, dict) and "error_description" in body:
                    error_detail = body["error_description"]
                elif isinstance(body, dict) and "error" in body:
                    error_detail = body["error"]
            except Exception:
                pass  # Use default message if parsing fails
        raise HTTPException(status_code=status_code, detail=error_detail)
    except Exception as e:
        logger.exception(f"Unexpected error during token refresh: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during token refresh."
        )


@router.post("/api/auth/logout", summary="Revoke token (logout)")
async def logout_endpoint(request: RevokeRequest, http_request: Request):  # Inject original request if needed
    """
    Revokes the provided token (access or refresh) using Keycloak's revocation endpoint.
    Also attempts to remove the token from the Redis cache if it's an access token.
    """
    if not request.token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token to revoke is required.")

    # 1. Attempt to remove from cache (if it's likely an access token)
    if request.token_type_hint == "access_token":
        # FIX: Use consistent and secure cache key generation
        token_cache_key = generate_cache_key(request.token)
        try:
            # FIX: Add await
            deleted_count = await redis_client.delete(token_cache_key)
            if deleted_count > 0:
                logger.debug(f"Removed token from cache during logout: {token_cache_key}")
            else:
                logger.debug(f"Token not found in cache during logout or already expired: {token_cache_key}")
        except RedisError as e:
            logger.error(f"Redis error deleting token from cache during logout: {e}")
            # Continue with revocation attempt anyway

    # 2. Call Keycloak Revocation Endpoint
    # This requires client authentication (secret or other method depending on client config)
    if not settings.keycloak_client_secret:
        logger.warning("Client secret not configured. Token revocation might fail if Keycloak requires it.")
        # Depending on Keycloak config for public clients, revocation might still work or might require PKI/signed JWTs

    payload = {
        "token": request.token,
        "token_type_hint": request.token_type_hint,
        "client_id": settings.KEYCLOAK_CLIENT_ID,
    }
    # Add secret only if configured
    if settings.KEYCLOAK_CLIENT_SECRET:
        payload["client_secret"] = settings.KEYCLOAK_CLIENT_SECRET

    try:
        async with httpx.AsyncClient(verify=True) as client:  # Ensure SSL verification
            response = await client.post(settings.revoke_url, data=payload)

            # Check response status - Keycloak might return 200 even if token unknown/invalid
            if response.status_code == 200:
                logger.info(f"Token revocation request sent successfully for token type {request.token_type_hint}.")
                # OIDC/OAuth2 spec says client shouldn't rely on revocation success confirmation
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"status": "logout_initiated", "message": "Logout request processed successfully."},
                )
            elif response.status_code == 400:
                # Log specific error if Keycloak provides one
                try:
                    error_data = response.json()
                    logger.warning(f"Token revocation failed (status {response.status_code}): {error_data}")
                    error_detail = error_data.get("error_description", "Revocation failed (client error)")
                except Exception:
                    logger.warning(f"Token revocation failed (status {response.status_code}): {response.text}")
                    error_detail = "Revocation failed (client error)"
                # Still return a success-like response to the client for logout UX
                return JSONResponse(
                    status_code=status.HTTP_200_OK,  # Or maybe 207 Multi-Status? 200 is simpler.
                    content={
                        "status": "logout_processed_with_errors",
                        "message": "Logout processed, but server-side revocation may have failed.",
                    },
                )

            else:
                # Handle other errors (5xx, etc.)
                logger.error(f"Token revocation failed with status {response.status_code}: {response.text}")
                # Return success to client, but log the server error
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "status": "logout_processed_with_errors",
                        "message": "Logout processed, but encountered a server error during revocation.",
                    },
                )

    except httpx.RequestError as e:
        logger.error(f"HTTP error during token revocation request to {settings.revoke_url}: {e}")
        # Return success to client, as the error is in communicating with Keycloak
        return JSONResponse(
            status_code=status.HTTP_200_OK,  # Or 503 if you want to indicate backend issue
            content={
                "status": "logout_processed_with_errors",
                "message": "Logout processed, but could not reach authentication server.",
            },
        )
    except Exception as e:
        logger.exception(f"Unexpected error during token revocation: {e}")
        # Return success to client
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "logout_processed_with_errors",
                "message": "Logout processed, but an unexpected error occurred.",
            },
        )
