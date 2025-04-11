import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserPublic(BaseModel):
    id: int
    keycloak_id: UUID
    username: str
    email: EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
