from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_PATTERN = r"^[A-Za-z0-9_]+$"
EMAIL_PATTERN = r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$"
MESSAGE_MAX_LENGTH = 2000

class IncomingMessage(BaseModel):
    """Client -> server. Unknown fields (e.g. a forged `sender`) are rejected."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["message"]
    content: str = Field(min_length=1, max_length=MESSAGE_MAX_LENGTH)

    @field_validator("content", mode="before")
    @classmethod
    def strip_content(cls, value):
        if isinstance(value, str):
            return value.strip()
        return value


class OutgoingMessage(BaseModel):
    """Server -> client. `sender` is set by the server from the authenticated user."""

    type: Literal["message"] = "message"
    sender: str
    content: str

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_PATTERN)
    email: str = Field(max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        if isinstance(value, str):
            return value.strip().lower()
        return value


class UserLogin(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"