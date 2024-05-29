import uuid
from pydantic import (
    BaseModel,
    EmailStr,
    constr,
    Field,
    SecretStr,
    model_validator,
    field_validator,
)
from datetime import date, datetime

from typing_extensions import Self

import re


class LoginRequest(BaseModel):
    username: str
    password: str

    @classmethod
    @field_validator('username')
    def username_validator(cls, password: str) -> str:
        if len(password) < 7:
            raise ValueError(
                'Username must be longer than 7 characters'
            )

        if not re.match(r'^[A-Z][a-z]+$', password):
            raise ValueError(
                'Username must start with an uppercase letter and contain only letters of the Latin alphabet'
            )

        return password.title()

    @model_validator(mode='after')
    def passwords__validator(self) -> Self:
        if len(self.password) < 8:
            raise ValueError(
                'Password must be longer than 8 characters'
            )

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$', self.password):
            raise ValueError(
                'Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.'
            )

        return self


class RegisterRequest(LoginRequest):
    email: EmailStr
    c_password: str
    birthday: date

    @model_validator(mode='after')
    def passwords__validator(self) -> Self:

        if self.password != self.c_password:
            raise ValueError('Passwords do not match')

        return self


class User(BaseModel):
    username: str
    email: EmailStr
    birthday: date


class UserCreateDB(User):
    hashed_password: str


class UserUpdateDB(User):
    id: int
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "Bearer"


class TokenCreateDB(BaseModel):
    hashed_token: str
    exp: datetime
    user_id: int


class TokenUpdateDB(TokenCreateDB):
    id: int

