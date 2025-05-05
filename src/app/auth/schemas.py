from pydantic import BaseModel


class RefreshRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    token: str
    token_type_hint: str = "access_token"
