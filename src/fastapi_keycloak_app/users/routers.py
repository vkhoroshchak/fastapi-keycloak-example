from fastapi import APIRouter, Depends

from fastapi_keycloak_app.core.config import settings
from fastapi_keycloak_app.core.security import verify_token

router = APIRouter()


@router.get("/api/me", summary="Get current user info")
async def get_me(token_data: dict = Depends(verify_token)) -> dict:
    """Returns claims from the validated access token."""
    # You might want to filter sensitive claims before returning
    return {
        "sub": token_data.get("sub"),
        "preferred_username": token_data.get("preferred_username"),
        "email": token_data.get("email"),
        "roles": list(  # Combine roles for easier consumption
            set(token_data.get("realm_access", {}).get("roles", []))
            | set(token_data.get("resource_access", {}).get(settings.KEYCLOAK_CLIENT_ID, {}).get("roles", []))
        ),
        "expires_at": token_data.get("exp"),
        # Add other desired claims
    }
